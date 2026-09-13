"""Assembly for the experimental DRV319 read-only BMS register proxy.

Offsets here are relative to the plaintext application. The retired BMS poll
body supplies code space. Non-BMS traffic and BMS replies retain their original
handler. This is not a complete battery firmware or an implementation of BMS
flash/update commands.
"""

POLL_OFFSET = 0x720
PROXY_OFFSET = 0x740
HOOK_OFFSET = 0x3958

POLL_ASM = """
    ldr r1, =0x20000918
    movs r0, #80
    strh.w r0, [r1, #0x64]
    ldr r2, =0x20000270
    ldr r0, [r2]
    strh.w r0, [r1, #0x68]
    bx lr
"""

PROXY_ASM = """
    cmp r0, #1
    bne original
    ldrb r2, [r1, #1]
    cmp r2, #0x22
    bne original
    ldrb r2, [r1, #2]
    cmp r2, #1
    bne original
    ldrb r2, [r1]
    cmp r2, #3
    bne drop
    ldrb r3, [r1, #3]
    cmp r3, #0x80
    bhs drop
    ldrb r2, [r1, #4]
    cmp r2, #0
    beq drop
    cmp r2, #242
    bhi drop
    lsls r0, r3, #1
    adds r0, r0, r2
    cmp.w r0, #256
    bhi drop

    push {r4, r5, r6, lr}
    sub sp, #8
    mov r4, r1
    mov r6, r2
    bl 0x720
    ldrb r3, [r4, #3]
    lsls r0, r3, #1
    ldr r5, =0x20000918
    adds r5, r5, r0
    str r5, [sp]
    movs r0, #0x25
    mov r1, r6
    movs r2, #1
    bl 0x5444
    add sp, #8
    pop {r4, r5, r6, pc}

drop:
    bx lr
original:
    b.w 0x37b4
"""


def assemble_proxy():
    import keystone
    assembler = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)

    def asm(source, address):
        return bytes(assembler.asm(source, addr=address)[0])

    poll = asm(POLL_ASM, POLL_OFFSET)
    proxy = asm(PROXY_ASM, PROXY_OFFSET)
    hook = asm("b.w 0x740", HOOK_OFFSET)
    if len(poll) > PROXY_OFFSET - POLL_OFFSET or PROXY_OFFSET + len(proxy) > 0x8D8:
        raise ValueError("Proxy does not fit inside retired BMS poll code")
    if len(hook) != 4:
        raise ValueError("Dispatcher hook must remain four bytes")
    return ((POLL_OFFSET, poll), (PROXY_OFFSET, proxy), (HOOK_OFFSET, hook))
