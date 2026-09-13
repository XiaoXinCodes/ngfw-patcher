"""Protocol-path checks; UART hardware timing and real dashboard are not modeled."""

import hashlib
import json
from pathlib import Path
import struct
import unittest

from drv319_nobms import APPLICATION_ADDRESS, patch_stock
import test_drv319_nobms as firmware_tests


class TestBMSReadProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        firmware_tests.TestDRV319NoBMS.setUpClass()
        cls.fixture = firmware_tests.TestDRV319NoBMS()
        cls.stock = cls.fixture.stock
        cls.image, cls.report = patch_stock(cls.stock)

    def machine(self, image=None):
        cpu, errors = self.fixture.drive_machine(self.image if image is None else image,
                                                absent=True, mode=0)
        cpu.mem_write(0x20000396, b"\x04")  # original dashboard queue: four free slots
        return cpu, errors

    def request(self, cpu, packet, source=1):
        from unicorn import arm_const as arm
        cpu.mem_write(0x20003000, bytes(packet))
        cpu.reg_write(arm.UC_ARM_REG_R0, source)
        cpu.reg_write(arm.UC_ARM_REG_R1, 0x20003000)
        self.fixture.call_on(cpu, 0x3938)

    @staticmethod
    def frame(cpu, slot=0):
        base = 0x2000111C + 256 * slot
        length = int.from_bytes(cpu.mem_read(base, 4), "little")
        if length > 250:
            raise AssertionError("Frame length exceeds native queue slot")
        return bytes(cpu.mem_read(base + 4, length))

    def assert_response(self, frame, register, data, device=0x25):
        body = bytes((len(data) + 2, device, 1, register)) + data
        expected = b"\x55\xaa" + body + struct.pack("<H", (~sum(body)) & 0xFFFF)
        self.assertEqual(frame, expected)

    def test_bms_percentage_query_now_gets_a_checked_reply(self):
        for image, expected in ((self.stock, False), (self.image, True)):
            cpu, _ = self.machine(image)
            self.request(cpu, (3, 0x22, 1, 0x32, 2))
            frame = self.frame(cpu)
            if expected:
                self.assert_response(frame, 0x32, struct.pack("<H", 80))
                self.assertEqual(bytes(cpu.mem_read(0x20000396, 1)), b"\x03")
            else:
                self.assertEqual(frame, b"")

    def test_voltage_reply_uses_controller_adc_and_register_boundaries(self):
        for voltage in (2900, 3600, 4200):
            cpu, _ = self.machine()
            cpu.mem_write(0x20000270, struct.pack("<I", voltage))
            self.request(cpu, (3, 0x22, 1, 0x34, 2))
            self.assert_response(self.frame(cpu), 0x34, struct.pack("<H", voltage))
        for reg, size in ((0, 242), (7, 242), (0x7F, 2), (0x7F, 1)):
            cpu, _ = self.machine()
            cpu.mem_write(0x20000918, bytes(range(256)))
            self.request(cpu, (3, 0x22, 1, reg, size))
            expected = bytes(cpu.mem_read(0x20000918 + 2 * reg, size))
            self.assert_response(self.frame(cpu), reg, expected)

    def test_malformed_reads_do_not_enqueue_or_modify_state(self):
        for packet in ((2, 0x22, 1, 0x32), (4, 0x22, 1, 0x32, 2, 0),
                       (3, 0x22, 1, 0x80, 2), (3, 0x22, 1, 0x32, 0),
                       (3, 0x22, 1, 0, 243), (3, 0x22, 1, 0x7F, 3)):
            cpu, _ = self.machine()
            before = bytearray(cpu.mem_read(0x20000000, 0x2F00))
            # The original dispatcher records source port 1 before our hook.
            before[0x451] = 1
            self.request(cpu, packet)
            self.assertEqual(bytes(cpu.mem_read(0x20000000, 0x2F00)), bytes(before))

    def test_native_dashboard_reads_preserve_reply_and_speed_value(self):
        for register, value in ((0, 0x319), (0x26, 600)):
            replies = []
            for image in (self.stock, self.image):
                cpu, _ = self.machine(image)
                cpu.mem_write(0x2000070A + 2 * register, struct.pack("<H", value))
                self.request(cpu, (3, 0x20, 1, register, 2))
                replies.append(self.frame(cpu))
            self.assertEqual(*replies)
            self.assert_response(replies[1], register, struct.pack("<H", value), device=0x23)

    def test_non_read_bms_commands_keep_original_behavior(self):
        for command in (3, 7, 8, 9, 10):
            results = []
            for image in (self.stock, self.image):
                cpu, _ = self.machine(image)
                self.request(cpu, (4, 0x22, command, 0x32, 80, 0))
                results.append(bytes(cpu.mem_read(0x20000000, 0x2F00)))
            self.assertEqual(*results)
        # Genuine inbound BMS replies (source port 0) are not handled as requests.
        states = []
        for image in (self.stock, self.image):
            cpu, _ = self.machine(image)
            self.request(cpu, (4, 0x25, 1, 0x32, 77, 0), source=0)
            states.append(bytes(cpu.mem_read(0x20000000, 0x2F00)))
        self.assertEqual(*states)

    def test_queue_saturation_does_not_overwrite_pending_frames(self):
        cpu, _ = self.machine()
        for _ in range(4):
            self.request(cpu, (3, 0x22, 1, 0x32, 2))
        pending = bytes(cpu.mem_read(0x2000111C, 0x400))
        self.assertEqual(bytes(cpu.mem_read(0x20000396, 1)), b"\0")
        self.request(cpu, (3, 0x22, 1, 0x34, 2))
        self.assertEqual(bytes(cpu.mem_read(0x2000111C, 0x400)), pending)

    def test_response_reaches_original_uart_data_register(self):
        import unicorn as uc
        cpu, _ = self.machine()
        self.request(cpu, (3, 0x22, 1, 0x32, 2))
        frame = self.frame(cpu)
        # Model only the UART's TX-ready/complete flags; no wire timing.
        cpu.mem_write(0x40013800, struct.pack("<I", 0xC0))
        sent = []

        def capture(emu, access, address, size, value, user_data):
            if address == 0x40013804:
                sent.append(value & 0xFF)

        cpu.hook_add(uc.UC_HOOK_MEM_WRITE, capture)
        for _ in frame:
            self.fixture.call_on(cpu, 0x5150)
        self.assertEqual(bytes(sent), frame)

    def test_native_byte_receiver_accepts_checksum_and_rejects_bad_frames(self):
        from unicorn import arm_const as arm
        body = bytes((3, 0x22, 1, 0x32, 2))
        valid_frame = b"\x55\xaa" + body + struct.pack("<H", (~sum(body)) & 0xFFFF)
        for valid in (True, False):
            cpu, _ = self.machine()
            frame = bytearray(valid_frame)
            if not valid:
                frame[-1] ^= 1
            for byte in frame:
                cpu.reg_write(arm.UC_ARM_REG_R0, byte)
                self.fixture.call_on(cpu, 0x5384)
            if valid:
                self.assert_response(self.frame(cpu), 0x32, struct.pack("<H", 80))
            else:
                self.assertEqual(self.frame(cpu), b"")

    def test_drive_and_brake_sequence_is_unchanged(self):
        old, _ = self.fixture.drive_machine(self.stock, absent=False, mode=0)
        new, _ = self.machine()
        for speed, throttle, brake, ticks in ((0, 50, 50, 12), (2070, 50, 50, 2),
                                             (1380, 175, 50, 100), (2070, 150, 150, 100),
                                             (0, 50, 50, 20)):
            for _ in range(ticks):
                self.fixture.call_on(new, 0x720)
                self.assertEqual(self.fixture.drive_tick(old, speed, throttle, brake),
                                 self.fixture.drive_tick(new, speed, throttle, brake))

    def test_binary_manifest_and_preserved_regions(self):
        path = Path(__file__).parent / "firmware/1s/recovery/DRV319-BMSREAD-FULL-EXPERIMENTAL.bin"
        full = path.read_bytes()
        self.assertEqual(full[0x1000:0x1000 + len(self.image)], self.image)
        audit = json.loads(path.with_suffix(".bin.json").read_text())
        self.assertEqual(audit["application_sha256"], self.report["output_sha256"])
        self.assertEqual(audit["sha256"], hashlib.sha256(full).hexdigest())
        self.assertEqual(hashlib.sha256(self.image).hexdigest(), self.report["output_sha256"])
        allowed = set()
        for change in self.report["changes"]:
            offset = int(change["offset"], 16)
            allowed.update(range(offset, offset + len(bytes.fromhex(change["after"])) ))
        actual = {i for i, pair in enumerate(zip(self.stock, self.image)) if pair[0] != pair[1]}
        self.assertTrue(actual <= allowed)
        # Core UART receive/transmit, Hall processing, and kick-start gate.
        for start, end in ((0x20F8, 0x213E), (0x50E8, 0x54B0), (0x2280, 0x24DC),
                           (0x6078, 0x6140), (0x13CC, 0x1652)):
            self.assertEqual(self.image[start:end], self.stock[start:end])


if __name__ == "__main__":
    unittest.main()
