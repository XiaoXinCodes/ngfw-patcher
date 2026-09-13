"""Build the checked DRV319 no-BMS application with fixed 80% and read proxy.

Use build_1s_recovery.py to wrap it in a full ST-Link image.
"""

from dataclasses import dataclass
import hashlib
import struct


STOCK_SHA256 = "c983d44ab7c68ff4c7b72e09ec7b862b009e00e8b2105a5f0a33bfc85b152387"
STOCK_SIZE = 28148
APPLICATION_ADDRESS = 0x08001000


@dataclass(frozen=True)
class Change:
    name: str
    offset: int
    context: str
    target: int | None = None
    payload: str | None = None

    def replacement(self):
        if self.payload is not None:
            return bytes.fromhex(self.payload)
        if self.target is None:
            return bytes.fromhex("7047")  # BX LR before the function prologue
        displacement = self.target - (self.offset + 4)
        if displacement % 2 or not -2048 <= displacement <= 2046:
            raise ValueError("Invalid Thumb B.n displacement")
        return struct.pack("<H", 0xE000 | ((displacement // 2) & 0x7FF))


# Offsets are in the plaintext application, not in a complete flash dump.
# Leave the ESC serial check (error 35), controller temperature check (40),
# ADC voltage derating and startup voltage check (24) intact.
CHANGES = (
    Change("bms_tx_enqueue_return", 0x5754, "2de9fc41174c089f"),
    Change("skip_bms_errors_21_23", 0x1F58, "687d012802d095f8", 0x1F78),
    Change("skip_bms_cold_derating", 0x5B10, "fd48b0f900000628", 0x5B30),
    Change("skip_bms_hot_derating", 0x5B48, "f448b0f900003228", 0x5B6C),
    Change("skip_bms_capacity_derating", 0x5BC2, "b0f964000a2801db", 0x5BCA),
    Change("skip_bms_timeout_limit_test", 0x5DF8, "687d01280ed095f8", 0x5E04),
    Change("skip_bms_serial_limit_test", 0x5E0C, "95f82f00012803d0", 0x5E14),
    Change("skip_bms_timeout_error", 0x5E30, "687d012802d095f8", 0x5E42),
    Change("skip_bms_serial_error", 0x5E50, "95f82f00012802d1", 0x5E5E),
    # Keep R1's battery-buffer pointer load at 0x5EF2 and the ADC-based
    # undervoltage hysteresis at 0x5F48..0x5F82. Do not port DRV155's larger jump.
    Change("skip_bms_remaining_capacity_limit", 0x5EF4, "b1f9620064281fda", 0x5F48),
)


def patch_stock(data: bytes) -> tuple[bytes, dict]:
    if len(data) != STOCK_SIZE or hashlib.sha256(data).hexdigest() != STOCK_SHA256:
        raise ValueError("Expected the exact unmodified 1S DRV319 application; input rejected")
    from drv319_bms_proxy import assemble_proxy
    names = ("bms_poll_fixed80_adc_voltage", "bms_read_proxy", "bms_dispatch_hook")
    changes = tuple(Change(name, offset, data[offset:offset + len(payload)].hex(),
                           payload=payload.hex())
                    for name, (offset, payload) in zip(names, assemble_proxy())) + CHANGES
    for change in changes:
        context = bytes.fromhex(change.context)
        if data[change.offset:change.offset + len(context)] != context:
            raise ValueError(f"Unexpected instruction context at {change.offset:#x}")
    output = bytearray(data)
    entries = []
    for change in changes:
        replacement = change.replacement()
        output[change.offset:change.offset + len(replacement)] = replacement
        entries.append({
            "name": change.name,
            "offset": hex(change.offset),
            "before": data[change.offset:change.offset + len(replacement)].hex(),
            "after": replacement.hex(),
            "branch_target": None if change.target is None else hex(change.target),
        })
    result = bytes(output)
    report = {
        "status": "custom_drv319_bms_read_proxy",
        "model": "1s",
        "base": "DRV319",
        "image_type": "application_only",
        "application_address": hex(APPLICATION_ADDRESS),
        "input_sha256": STOCK_SHA256,
        "output_sha256": hashlib.sha256(result).hexdigest(),
        "size": len(result),
        "changed_bytes": sum(a != b for a, b in zip(data, result)),
        "battery_gauge": "fixed_80_percent_NOT_measured",
        "assumptions": [
            "Battery has its own protection BMS; Xiaomi BMS data lines are disconnected",
            "Original controller voltage limits are suitable for the battery",
            "Application is combined with a compatible bootloader and personalized device data",
        ],
        "changes": entries,
    }
    report["bms_protocol"] = "read_only_cached_register_proxy"
    report["bms_protocol_limits"] = [
        "Decoded legacy BMS read requests from the dashboard interface only",
        "SOC is fixed at 80; total voltage is copied from the controller ADC value",
        "Other fields are cached/uninitialized values, not real battery measurements",
        "No BMS firmware update/write emulation, cell measurements or real pack identity",
        "Hardware confirmation applies only to the published board-specific full image",
    ]
    return result, report
