import hashlib
from pathlib import Path
import struct
import unittest

from build_1s_recovery import ASSETS, build_recovery


class TestRecoveryImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = (Path(__file__).parent / "recovery_assets/1s/DRV319-stock.bin").read_bytes()
        # Synthetic identity used only inside tests, never published as firmware.
        cls.uid = struct.pack("<III", 0x12345678, 0x9ABCDEF0, 0x87654321)
        cls.serial = "12345/12345678"

    def test_layout_matches_upstream_three_write_operations(self):
        image, report = build_recovery(self.application, self.uid, self.serial, km="123.456")
        boot = (ASSETS / "boot.bin").read_bytes()
        template = bytearray((ASSETS / "data-template.bin").read_bytes())
        # Independent reproduction of the offsets used in flash_m365_1S.py.
        template[0x20:0x2E] = self.serial.encode()
        for index, word in enumerate(struct.unpack("<III", self.uid)):
            struct.pack_into("<I", template, 0x1B4 + 4 * index, word)
        struct.pack_into("<I", template, 0x52, 123456)
        self.assertEqual(len(image), 65536)
        self.assertEqual(image[:len(boot)], boot)
        self.assertEqual(image[0x1000:0x1000 + len(self.application)], self.application)
        self.assertEqual(image[0xF800:0xFA00], bytes(template))
        for start, end in ((len(boot), 0x1000), (0x1000 + len(self.application), 0xF800),
                           (0xFA00, 0x10000)):
            self.assertEqual(image[start:end], b"\xff" * (end - start))
        self.assertEqual(image[0xF9B4:0xF9C0], self.uid)
        self.assertEqual(report["sha256"], hashlib.sha256(image).hexdigest())

    def test_missing_or_erased_identity_rejected(self):
        for uid in (b"", self.uid[:-1], self.uid + b"\0", bytes(12), b"\xff" * 12):
            with self.assertRaises(ValueError):
                build_recovery(self.application, uid, self.serial)
        for serial in ("", "12345/1234567", "12345/123456789", "12345/1234567é"):
            with self.assertRaises(ValueError):
                build_recovery(self.application, self.uid, serial)

    def test_asset_or_application_mismatch_rejected(self):
        for options in ({"boot": b"bad"}, {"template": b"bad"}):
            with self.assertRaises(ValueError):
                build_recovery(self.application, self.uid, self.serial, **options)
        with self.assertRaises(ValueError):
            build_recovery(bytes([self.application[0] ^ 1]) + self.application[1:], self.uid, self.serial)

    def test_odometer_validation_and_explicit_unknown_report(self):
        for km in ("-1", "NaN", "Infinity", "4294967.296", "0.0001"):
            with self.assertRaises(ValueError):
                build_recovery(self.application, self.uid, self.serial, km=km)
        image, report = build_recovery(self.application, self.uid, self.serial)
        self.assertEqual(image[0xF852:0xF856], bytes(4))
        self.assertEqual(report["odometer_source"], "unknown_reset_to_zero")

    def test_confirmed_full_image_rebuilds_byte_for_byte(self):
        import json
        from drv319_nobms import patch_stock
        path = Path(__file__).parent / "firmware/1s/recovery/DRV319-BMSREAD-FULL-EXPERIMENTAL.bin"
        report = json.loads(path.with_suffix(".bin.json").read_text())
        application, _ = patch_stock(self.application)
        image, _ = build_recovery(application, bytes.fromhex(report["uid_bytes_at_0x1FFFF7E8"]),
                                  report["serial"], replacement_serial=True)
        self.assertEqual(image, path.read_bytes())
        self.assertEqual(hashlib.sha256(image).hexdigest(), report["sha256"])

    def test_authorized_replacement_is_not_reported_as_original(self):
        _, report = build_recovery(self.application, self.uid, "25699/01234567",
                                   replacement_serial=True)
        self.assertEqual(report["serial_source"], "authorized_replacement_not_original")

    def test_original_initialization_loads_serial_and_refreshes_factory_uid(self):
        try:
            from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
            from unicorn import arm_const as arm
        except ImportError:
            self.skipTest("Install requirements-1s.txt for ARM initialization checks")
        serial = "25699/01234567"
        image, _ = build_recovery(self.application, self.uid, serial, replacement_serial=True)
        for matching in (True, False):
            with self.subTest(factory_uid_matches=matching):
                cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
                cpu.mem_map(0x08000000, 0x10000)
                cpu.mem_write(0x08000000, image)
                cpu.mem_map(0x20000000, 0x5000)
                cpu.mem_map(0x1FFFF000, 0x1000)
                cpu.mem_map(0x40000000, 0x30000)
                factory_uid = self.uid if matching else bytes([self.uid[0] ^ 1]) + self.uid[1:]
                cpu.mem_write(0x1FFFF7E8, factory_uid)
                # Run the real C runtime initializer, including compressed data
                # initialization, stopping before main/peripheral initialization.
                cpu.emu_start(0x080010ED, 0x080077FC, count=100000)
                self.assertEqual(cpu.reg_read(arm.UC_ARM_REG_PC), 0x080077FC)
                cpu.reg_write(arm.UC_ARM_REG_SP, 0x20004F00)
                cpu.reg_write(arm.UC_ARM_REG_LR, 0x0800FFE1)
                cpu.emu_start(0x080074DD, 0x0800FFE0, count=30000)
                self.assertEqual(cpu.reg_read(arm.UC_ARM_REG_PC), 0x0800FFE0)
                self.assertEqual(bytes(cpu.mem_read(0x2000072A, 14)), serial.encode())
                # DRV319's 0x40A4 routine refreshes the RAM UID from system
                # memory before comparing it; don't assume a stale flash copy
                # necessarily produces error 27 on this version.
                self.assertEqual(bytes(cpu.mem_read(0x200008BE, 12)), factory_uid)
                self.assertEqual(bytes(cpu.mem_read(0x20000706, 1)), b"\x01")  # 1S prefix
                self.assertEqual(bytes(cpu.mem_read(0x200006EB, 1)), b"\0")  # SN valid
                self.assertEqual(bytes(cpu.mem_read(0x20000001, 1)), b"\0")
                self.assertEqual(bytes(cpu.mem_read(0x0800F800, 512)), image[0xF800:0xFA00])


if __name__ == "__main__":
    unittest.main()
