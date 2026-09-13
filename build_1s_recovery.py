"""Build a complete 64-KiB STM32 1S recovery image after flash erasure.

Uses the layout and personalization fields in CamiAlfa/M365_DRV_STLINK's
flash_m365_1S.py. Does not connect to hardware, change RDP, or flash anything.
Requires the actual chip UID and an explicitly chosen scooter serial number.
An authorized replacement serial is recorded as such, not as the original identity.
"""

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "recovery_assets/1s"
UPSTREAM = "b4e03683d5f9fe6981a615855e2e3d34c36ab844"
BOOT_SHA256 = "7f5574cb1233653db95e8cc4baf2b99f446ffb973e01651cde190f013262016a"
DATA_SHA256 = "4385da291edd2284fadd9d055ee182d2f22bb36efd28f27946206162d43d3ce6"
APPLICATIONS = {
    "c983d44ab7c68ff4c7b72e09ec7b862b009e00e8b2105a5f0a33bfc85b152387": "DRV319 stock",
    "3d22467450037e43722e25ff3268cb50f1515cc6ff8317e69dcb97eae3b8de0d": "DRV319 BMSREAD experimental",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_vectors(data, address):
    sp, reset = struct.unpack_from("<II", data)
    if not 0x20000000 < sp <= 0x20005000 or sp % 4:
        raise ValueError("Initial stack pointer is outside STM32F103C8 SRAM")
    if not reset & 1 or not address <= (reset & ~1) < address + len(data):
        raise ValueError("Reset vector does not point into its image at the specified address")


def build_recovery(application, uid, serial, *, km=None, boot=None, template=None,
                   replacement_serial=False):
    boot = (ASSETS / "boot.bin").read_bytes() if boot is None else boot
    template = (ASSETS / "data-template.bin").read_bytes() if template is None else template
    if digest(boot) != BOOT_SHA256 or len(boot) != 3104:
        raise ValueError("Bootloader does not match the verified upstream asset")
    if digest(template) != DATA_SHA256 or len(template) != 512:
        raise ValueError("Vehicle data template does not match the verified upstream asset")
    app_hash = digest(application)
    if app_hash not in APPLICATIONS or len(application) != 28148:
        raise ValueError("Unknown application: expected one of this repository's checked DRV319 images")
    if len(uid) != 12 or uid in (bytes(12), b"\xff" * 12):
        raise ValueError("Supply the actual 12-byte chip UID read from 0x1FFFF7E8")
    if not re.fullmatch(r"[0-9]{5}/[0-9]{8}", serial):
        raise ValueError("Expected a scooter serial in the form 12345/12345678")
    kilometers = Decimal(0) if km is None else Decimal(str(km))
    if not kilometers.is_finite() or not Decimal(0) <= kilometers <= Decimal(0xFFFFFFFF) / 1000:
        raise ValueError("Odometer must be a finite, nonnegative value fitting the meter counter")
    meters = kilometers * 1000
    if meters != meters.to_integral_value():
        raise ValueError("Odometer precision is one meter (0.001 km)")
    validate_vectors(boot, 0x08000000)
    validate_vectors(application, 0x08001000)

    personalized = bytearray(template)
    personalized[0x20:0x2E] = serial.encode("ascii")
    personalized[0x1B4:0x1C0] = uid
    struct.pack_into("<I", personalized, 0x52, int(meters))
    image = bytearray(b"\xff" * 0x10000)
    image[:len(boot)] = boot
    image[0x1000:0x1000 + len(application)] = application
    image[0xF800:0xFA00] = personalized
    result = bytes(image)
    return result, {
        "image_type": "full_flash_recovery_64KiB",
        "flash_address": "0x08000000",
        "size": len(result),
        "sha256": digest(result),
        "application": APPLICATIONS[app_hash],
        "application_sha256": app_hash,
        "boot_sha256": BOOT_SHA256,
        "data_template_sha256": DATA_SHA256,
        "upstream_commit": UPSTREAM,
        "serial": serial,
        "serial_source": "authorized_replacement_not_original" if replacement_serial else "user_supplied",
        "uid_bytes_at_0x1FFFF7E8": uid.hex(),
        "uid_words_little_endian": [f"0x{x:08X}" for x in struct.unpack("<III", uid)],
        "odometer_meters": int(meters),
        "odometer_source": "unknown_reset_to_zero" if km is None else "user_supplied",
        "vehicle_data_source": "upstream_recovery_template_personalized_not_original_backup",
        "regions": {"boot": "0x08000000", "application": "0x08001000", "vehicle_data": "0x0800F800"},
        "hardware_validation": "not_performed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--stock", action="store_true",
                        help="Use unmodified DRV319 instead of the no-BMS patch")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--replacement-serial", action="store_true",
                        help="Record an explicitly authorized replacement serial, not the original")
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--uid-file", type=Path, help="12 raw bytes saved from 0x1FFFF7E8")
    identity.add_argument("--uid-words", nargs=3, metavar=("WORD0", "WORD1", "WORD2"),
                          help="Three 32-bit hexadecimal words shown at 0x1FFFF7E8/Ec/F0")
    parser.add_argument("--km", help="Known odometer in km; if unknown, the erased counter is reset to zero")
    args = parser.parse_args()
    report_path = args.output.with_suffix(args.output.suffix + ".json")
    if args.output.exists() or report_path.exists():
        parser.error("Output or report exists; choose a different filename")
    try:
        uid = (args.uid_file.read_bytes() if args.uid_file else
               struct.pack("<III", *(int(word, 16) for word in args.uid_words)))
        application = (ASSETS / "DRV319-stock.bin").read_bytes()
        patch_report = None
        if not args.stock:
            from drv319_nobms import patch_stock
            application, patch_report = patch_stock(application)
        result, report = build_recovery(application, uid, args.serial, km=args.km,
                                        replacement_serial=args.replacement_serial)
        if patch_report is not None:
            report["application_patch"] = patch_report
    except (OSError, ValueError, ArithmeticError, struct.error, ImportError) as exc:
        parser.error(str(exc))
    with args.output.open("xb") as stream:
        stream.write(result)
    with report_path.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"Full recovery image: {args.output} (65536 bytes at 0x08000000)")
    print(f"Audit: {report_path}")
    if args.km is None:
        print("Original odometer unavailable: recovery data sets it to zero.")
    print("Layout checked; actual hardware startup remains unverified.")


if __name__ == "__main__":
    main()
