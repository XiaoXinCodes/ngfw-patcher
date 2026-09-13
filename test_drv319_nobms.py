"""ARM behavior checks for the single maintained no-BMS build."""

import hashlib
from pathlib import Path
import struct
import unittest

from drv319_nobms import APPLICATION_ADDRESS, CHANGES, STOCK_SHA256, patch_stock


class TestDRV319NoBMS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / "recovery_assets/1s/DRV319-stock.bin"
        cls.stock = path.read_bytes()
        cls.patched, cls.report = patch_stock(cls.stock)

    def test_exact_input_and_repeat_patch_rejected(self):
        for invalid in (b"", self.stock[:-1], self.patched,
                        bytes([self.stock[0] ^ 1]) + self.stock[1:]):
            with self.subTest(size=len(invalid)):
                with self.assertRaises(ValueError):
                    patch_stock(invalid)

    def test_only_declared_bytes_changed(self):
        allowed = {i for c in self.report["changes"]
                   for i in range(int(c["offset"], 16),
                                  int(c["offset"], 16) + len(bytes.fromhex(c["after"])))}
        actual = {i for i, (a, b) in enumerate(zip(self.stock, self.patched)) if a != b}
        self.assertEqual(len(self.stock), len(self.patched))
        self.assertTrue(actual <= allowed)
        self.assertEqual(len(actual), self.report["changed_bytes"])
        self.assertEqual(hashlib.sha256(self.stock).hexdigest(), STOCK_SHA256)

    def test_branch_targets_and_function_returns(self):
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        for c in CHANGES:
            with self.subTest(change=c.name):
                instruction = next(decoder.disasm(self.patched[c.offset:c.offset + 2], c.offset))
                if c.target is None:
                    self.assertEqual((instruction.mnemonic, instruction.op_str), ("bx", "lr"))
                else:
                    self.assertEqual(instruction.mnemonic, "b")
                    self.assertEqual(int(instruction.op_str.lstrip("#"), 0), c.target)

    def machine(self, image, *, absent=False, voltage=3600, mode=1,
                serial_error=False, temperature_error=False, ready=True,
                execute_error_handler=False):
        import unicorn as uc
        from unicorn import arm_const as arm
        emu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB | uc.UC_MODE_MCLASS)
        emu.mem_map(0x08000000, 0x10000)
        emu.mem_write(APPLICATION_ADDRESS, image)
        emu.mem_map(0x20000000, 0x5000)  # STM32F103C8: 20 KiB SRAM
        emu.reg_write(arm.UC_ARM_REG_SP, 0x20004F00)
        emu.reg_write(arm.UC_ARM_REG_LR, 0x0800FFE1)
        state, limits, battery, registers = 0x200006C4, 0x200003CC, 0x20000918, 0x2000070A

        def put(addr, val, fmt="B"):
            emu.mem_write(addr, struct.pack("<" + fmt, val))

        put(0x20000270, voltage, "I")
        put(state + 0x22, 0 if absent else 1)
        put(state + 0x15, 1 if absent else 0)
        put(state + 0x2F, 1 if absent else 0)
        put(state + 0x32, 0 if absent else 1)
        put(state + 0x30, 1)  # enable the secondary error-check state machine
        put(state + 0x27, int(serial_error))
        put(state + 0x33, int(temperature_error))
        put(state + 0x3C, int(mode == 1))
        put(state + 0x3D, int(mode == 2))
        put(limits + 0x0C, int(ready))
        put(limits + 0x3A, 601 if ready else 0, "H")
        put(0x20000458 + 6, 1)  # state for the second BMS error path
        put(registers + 0x3A, 0x800, "H")  # dashboard authentication already complete
        put(registers + 0xF6, 0, "H")  # original KERS selection
        put(battery + 0x62, 0 if absent else 1000, "H")
        put(battery + 0x64, 0 if absent else 80, "H")
        for addr in (0x2000024C, 0x2000024E):
            put(addr, 0 if absent else 25, "h")

        errors = []
        # Isolate the limit-selection routine from the global error handler.
        # The actual motor, interrupts, ADC hardware, bootloader and dashboard
        # protocol are NOT simulated by these tests.
        def hook(cpu, address, size, user_data):
            if address == APPLICATION_ADDRESS + 0x4880:
                errors.append(cpu.reg_read(arm.UC_ARM_REG_R0))
                if not execute_error_handler:
                    cpu.reg_write(arm.UC_ARM_REG_PC, cpu.reg_read(arm.UC_ARM_REG_LR))

        emu.hook_add(uc.UC_HOOK_CODE, hook)
        return emu, errors

    def run_function(self, image, offset=0x5B0C, **kwargs):
        from unicorn import arm_const as arm
        emu, errors = self.machine(image, **kwargs)
        emu.emu_start(APPLICATION_ADDRESS + offset + 1, 0x0800FFE0, count=10000)
        self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), 0x0800FFE0,
                         "Function did not return within instruction budget")
        self.assertEqual(emu.reg_read(arm.UC_ARM_REG_SP), 0x20004F00)
        return emu, errors

    @staticmethod
    def limit_values(emu):
        # KERS selection, speed/current limits and derating factors.
        base = 0x200003CC
        return tuple(struct.unpack("<H", emu.mem_read(base + o, 2))[0]
                     for o in (0x22, 0x26, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38,
                               0x1A, 0x1C, 0x1E, 0x2C))

    def test_no_bms_matches_healthy_stock_limits_in_all_modes(self):
        for mode in (0, 1, 2):
            for voltage in (3500, 3600, 4100):
                with self.subTest(mode=mode, voltage=voltage):
                    stock, stock_errors = self.run_function(self.stock, mode=mode, voltage=voltage)
                    patched, errors = self.run_function(self.patched, absent=True,
                                                       mode=mode, voltage=voltage)
                    self.assertEqual(stock_errors, [])
                    self.assertEqual(errors, [])
                    self.assertEqual(self.limit_values(stock), self.limit_values(patched))

    def test_bms_faults_removed_but_other_errors_preserved(self):
        for offset in (0x1F04, 0x5B0C):
            with self.subTest(offset=hex(offset)):
                _, old_errors = self.run_function(self.stock, offset, absent=True)
                self.assertIn(21, old_errors)
                self.assertIn(23, old_errors)
                _, errors = self.run_function(self.patched, offset, absent=True)
                self.assertNotIn(21, errors)
                self.assertNotIn(23, errors)
        for flag, error in (("serial_error", 35), ("temperature_error", 40)):
            with self.subTest(flag=flag):
                stock, old_errors = self.run_function(self.stock, **{flag: True})
                patched, errors = self.run_function(self.patched, absent=True, **{flag: True})
                self.assertIn(error, old_errors)
                self.assertIn(error, errors)
                self.assertEqual(self.limit_values(stock), self.limit_values(patched))

    def test_voltage_derating_preserved(self):
        normal, _ = self.run_function(self.patched, absent=True, voltage=3600)
        low, _ = self.run_function(self.patched, absent=True, voltage=2900)
        stock_low, _ = self.run_function(self.stock, voltage=2900)
        self.assertEqual(self.limit_values(low), self.limit_values(stock_low))
        self.assertLess(self.limit_values(low)[0], self.limit_values(normal)[0])
        self.assertLess(self.limit_values(low)[1], self.limit_values(normal)[1])

    def test_disabled_bms_tx_returns_without_ram_writes(self):
        from unicorn import arm_const as arm
        for offset in (0x5754,):
            emu, _ = self.machine(self.patched, absent=True)
            before = bytes(emu.mem_read(0x20000000, 0x5000))
            emu.emu_start(APPLICATION_ADDRESS + offset + 1, 0x0800FFE0, count=10)
            self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), 0x0800FFE0)
            self.assertEqual(bytes(emu.mem_read(0x20000000, 0x5000)), before)

    def test_no_bms_remains_usable_after_timeout(self):
        from unicorn import arm_const as arm
        for image, expected_fault in ((self.stock, True), (self.patched, False)):
            emu, errors = self.machine(image, absent=True, ready=False)
            for _ in range(605):
                emu.reg_write(arm.UC_ARM_REG_LR, 0x0800FFE1)
                emu.emu_start(APPLICATION_ADDRESS + 0x5B0D, 0x0800FFE0, count=10000)
                self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), 0x0800FFE0)
            self.assertEqual(21 in errors, expected_fault)
            if not expected_fault:
                healthy, _ = self.run_function(self.stock)
                self.assertEqual(self.limit_values(emu), self.limit_values(healthy))

    def test_undervoltage_hysteresis_preserved(self):
        from unicorn import arm_const as arm
        stock, _ = self.machine(self.stock)
        patched, _ = self.machine(self.patched, absent=True)
        for voltage, flag in ((2900, 1), (3300, 1), (3500, 0)):
            for emu in (stock, patched):
                emu.mem_write(0x20000270, struct.pack("<I", voltage))
                emu.reg_write(arm.UC_ARM_REG_LR, 0x0800FFE1)
                emu.emu_start(APPLICATION_ADDRESS + 0x5B0D, 0x0800FFE0, count=10000)
                self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), 0x0800FFE0)
                self.assertEqual(bytes(emu.mem_read(0x200006C4 + 0x35, 1)), bytes([flag]))
            self.assertEqual(self.limit_values(stock), self.limit_values(patched))

    def test_startup_voltage_gate_preserved(self):
        import unicorn as uc
        from unicorn import arm_const as arm
        for image in (self.stock, self.patched):
            for voltage in (2599, 2600, 3600, 4300, 4301):
                emu, errors = self.machine(image)
                emu.reg_write(arm.UC_ARM_REG_R0, voltage)

                def stop_retry(cpu, address, size, user_data):
                    if address == APPLICATION_ADDRESS + 0x2F0A:
                        cpu.emu_stop()

                emu.hook_add(uc.UC_HOOK_CODE, stop_retry)
                emu.emu_start(APPLICATION_ADDRESS + 0x2F43,
                              APPLICATION_ADDRESS + 0x2F56, count=100)
                self.assertEqual(errors, [24] if voltage < 2600 or voltage > 4300 else [])
                expected_pc = 0x2F0A if errors else 0x2F56
                self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC),
                                 APPLICATION_ADDRESS + expected_pc)

    def call_on(self, emu, offset):
        """Execute the actual function and all callees, with an execution limit."""
        from unicorn import arm_const as arm
        sp = emu.reg_read(arm.UC_ARM_REG_SP)
        emu.reg_write(arm.UC_ARM_REG_LR, 0x0800FFE1)
        emu.emu_start(APPLICATION_ADDRESS + offset + 1, 0x0800FFE0, count=30000)
        self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), 0x0800FFE0)
        self.assertEqual(emu.reg_read(arm.UC_ARM_REG_SP), sp)
        return emu.reg_read(arm.UC_ARM_REG_R0)

    def drive_machine(self, image, *, absent, mode=1):
        emu, errors = self.machine(image, absent=absent, mode=mode,
                                   execute_error_handler=True)
        # Memory-backed peripheral registers allow the actual register writes.
        # No timer, ADC conversion, MOSFET, motor or wheel dynamics are modeled.
        emu.mem_map(0x40000000, 0x30000)
        return emu, errors

    def drive_tick(self, emu, speed, throttle, brake=50):
        emu.mem_write(0x20000230, struct.pack("<i", speed))
        emu.mem_write(0x20000275, bytes((throttle, brake)))
        # This is the actual dispatcher: start gate, limits, register update,
        # throttle/brake processing and light handling. No callees are stubbed.
        self.call_on(emu, 0x6744)
        target = struct.unpack("<i", emu.mem_read(0x20000218, 4))[0]
        request = struct.unpack("<H", emu.mem_read(0x200018C6, 2))[0]
        control_gate = self.call_on(emu, 0x1B78)
        return target, request, control_gate

    def test_drive_brake_release_and_stop_match_stock(self):
        for mode in (0, 1, 2):
            stock, stock_errors = self.drive_machine(self.stock, absent=False, mode=mode)
            patched, errors = self.drive_machine(self.patched, absent=True, mode=mode)
            stages = (("idle", 0, 50, 50, 12),
                      ("kick", 2070, 50, 50, 2),
                      # At 6 km/h the stock 5 km/h pedestrian mode correctly
                      # requests no acceleration. After the kick, test at 4 km/h
                      # with full throttle, below the limits of all three modes.
                      ("drive", 1380, 175, 50, 100),
                      ("brake", 2070, 150, 150, 100),
                      ("release", 2070, 50, 50, 100),
                      ("stop", 0, 50, 50, 20))
            for name, speed, throttle, brake, ticks in stages:
                with self.subTest(mode=mode, stage=name):
                    for _ in range(ticks):
                        expected = self.drive_tick(stock, speed, throttle, brake)
                        actual = self.drive_tick(patched, speed, throttle, brake)
                        self.assertEqual(actual, expected)
                    if name == "drive":
                        self.assertGreater(actual[0], 0)
                        self.assertEqual(actual[1:], (1, 2))
                    elif name == "brake":
                        self.assertLess(actual[0], 0)
                    elif name == "stop":
                        self.assertEqual(actual, (0, 0, 0))
            self.assertEqual(stock_errors, [])
            self.assertEqual(errors, [])

    def test_throttle_does_not_bypass_kick_start(self):
        for image, absent in ((self.stock, False), (self.patched, True)):
            emu, _ = self.drive_machine(image, absent=absent, mode=0)
            for _ in range(12):
                self.drive_tick(emu, 0, 50)
            for _ in range(100):
                self.assertEqual(self.drive_tick(emu, 0, 150), (0, 0, 0))
            # The original threshold is 1725 internal speed units (5 * 345).
            self.drive_tick(emu, 1725, 50)
            self.assertEqual(self.drive_tick(emu, 1725, 150), (0, 0, 0))
            self.drive_tick(emu, 1726, 50)
            for _ in range(20):
                actual = self.drive_tick(emu, 1726, 150)
            self.assertGreater(actual[0], 0)
            self.assertEqual(actual[1:], (1, 2))

    def test_input_timeout_and_invalid_controls_still_disable_drive(self):
        for fault, code in (("timeout", 10), ("throttle", 14), ("brake", 15)):
            results = []
            for image, absent in ((self.stock, False), (self.patched, True)):
                emu, errors = self.drive_machine(image, absent=absent, mode=0)
                self.drive_tick(emu, 2070, 50)
                for _ in range(20):
                    active = self.drive_tick(emu, 2070, 150)
                self.assertGreater(active[0], 0)
                self.assertEqual(active[1:], (1, 2))
                for _ in range(105):
                    if fault == "timeout":
                        emu.mem_write(0x2000022C, struct.pack("<H", 101))
                    actual = self.drive_tick(emu, 2070, 0 if fault == "throttle" else 150,
                                             0 if fault == "brake" else 50)
                self.assertIn(code, errors)
                self.assertEqual(actual[1:], (0, 0))
                self.assertEqual(bytes(emu.mem_read(0x20000001, 1)), bytes([code]))
                results.append(actual)
            self.assertEqual(*results)

    def test_dashboard_authentication_does_not_require_bms_reply(self):
        from unicorn import arm_const as arm
        for valid in (False, True):
            for image, absent in ((self.stock, False), (self.patched, True)):
                emu, _ = self.drive_machine(image, absent=absent)
                emu.mem_write(0x2000070A + 0x3A, b"\0\0")
                uid = (0x12345678, 0x9ABCDEF0, 0x87654321)
                emu.mem_write(0x2000070A + 0x1B4, struct.pack("<III", *uid))
                packet = bytearray(16)
                packet[:4] = bytes((12, 0x20, 0x57, 0))
                struct.pack_into("<II", packet, 4,
                                 (~sum(uid) & 0xFFFFFFFF) ^ int(not valid),
                                 ~(uid[0] * uid[1] * uid[2]) & 0xFFFFFFFF)
                emu.mem_write(0x20003000, bytes(packet))
                emu.reg_write(arm.UC_ARM_REG_R0, 1)
                emu.reg_write(arm.UC_ARM_REG_R1, 0x20003000)
                # Starts at the message dispatcher, not at a forced-success branch.
                # The supplied packet has already passed UART framing/decoding;
                # physical BLE firmware behavior is outside this test.
                self.call_on(emu, 0x3938)
                status = int.from_bytes(emu.mem_read(0x2000070A + 0x3A, 2), "little")
                self.assertEqual(bool(status & 0x800), valid)

    def test_repository_binary_matches_tested_build(self):
        image_path = Path(__file__).parent / "firmware/1s/recovery/DRV319-BMSREAD-FULL-EXPERIMENTAL.bin"
        self.assertEqual(image_path.read_bytes()[0x1000:0x1000 + len(self.patched)], self.patched)

    def test_main_loop_reaches_drive_dispatch_without_bms(self):
        import unicorn as uc
        from unicorn import arm_const as arm
        for absent in (False, True):
            image = self.patched if absent else self.stock
            emu, errors = self.drive_machine(image, absent=absent, mode=0)
            emu.mem_write(0x20000230, struct.pack("<i", 2070))
            emu.mem_write(0x20000275, bytes((50, 50)))
            emu.reg_write(arm.UC_ARM_REG_R4, 0x200006C4)
            emu.reg_write(arm.UC_ARM_REG_R6, 0)
            emu.reg_write(arm.UC_ARM_REG_R8, 0x200018B4)
            emu.reg_write(arm.UC_ARM_REG_R10, 0x20002F00)
            visited = []

            def track(cpu, address, size, user_data):
                if address == APPLICATION_ADDRESS + 0x6744:
                    visited.append(address)

            emu.hook_add(uc.UC_HOOK_CODE, track)
            # Start at the scheduler's charging/power gate, including its real
            # BMS charging-state reader 0x0D94. Stop at the loop continuation.
            # This is a scheduler fragment, not a simulation from power-on.
            emu.emu_start(APPLICATION_ADDRESS + 0x69A1,
                          APPLICATION_ADDRESS + 0x68C2, count=30000)
            self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), APPLICATION_ADDRESS + 0x68C2)
            self.assertEqual(visited, [APPLICATION_ADDRESS + 0x6744])
            self.assertEqual(bytes(emu.mem_read(0x200006C4 + 0x3A, 1)), b"\0")
            self.assertEqual(errors, [])


    def test_periodic_stub_writes_only_soc_voltage_and_preserves_callee_saved_registers(self):
        from unicorn import arm_const as arm
        for initial in (0, 1, 79, 100, 65535):
            emu, _ = self.drive_machine(self.patched, absent=True)
            emu.mem_write(0x2000097C, struct.pack("<H", initial))
            registers = [getattr(arm, f"UC_ARM_REG_R{i}") for i in range(4, 12)]
            for i, reg in enumerate(registers):
                emu.reg_write(reg, 0x13570000 + i)
            before = bytearray(emu.mem_read(0x20000000, 0x5000))
            self.call_on(emu, 0x720)
            before[0x97C:0x97E] = struct.pack("<H", 80)
            before[0x980:0x982] = struct.pack("<H", 3600)
            self.assertEqual(bytes(emu.mem_read(0x20000000, 0x5000)), bytes(before))
            self.assertEqual([emu.reg_read(r) for r in registers],
                             [0x13570000 + i for i in range(8)])
            self.assertEqual(self.call_on(emu, 0x3E68), 80)

    def test_original_telemetry_and_dashboard_buffer_receive_80(self):
        from unicorn import arm_const as arm
        emu, errors = self.drive_machine(self.patched, absent=True)
        self.call_on(emu, 0x720)
        emu.reg_write(arm.UC_ARM_REG_R4, 0x2000070A)
        emu.emu_start(APPLICATION_ADDRESS + 0x63DD, APPLICATION_ADDRESS + 0x63E8, count=100)
        self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), APPLICATION_ADDRESS + 0x63E8)
        for offset in (0x44, 0x168):
            self.assertEqual(int.from_bytes(emu.mem_read(0x2000070A + offset, 2), "little"), 80)
        emu.reg_write(arm.UC_ARM_REG_R5, 0x200006C4)
        emu.emu_start(APPLICATION_ADDRESS + 0x6425, APPLICATION_ADDRESS + 0x6446, count=100)
        self.assertEqual(emu.reg_read(arm.UC_ARM_REG_PC), APPLICATION_ADDRESS + 0x6446)
        self.assertEqual(bytes(emu.mem_read(0x20000011, 1)), bytes([80]))
        self.assertEqual(errors, [])



if __name__ == "__main__":
    unittest.main()
