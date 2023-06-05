from pwn import *
from ctypes import *

# p = remote('pwn.challenge.ctf.show', 28109)
p = process('./pwn/stack2')
elf = ELF('./pwn/stack2')
# libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.sendline(b'1')
p.sendline(b'1')
p.sendline(b'1')
gdb.attach(p, 'b printf')
pause()
p.sendline(b'1')
p.sendline(b'3')
p.sendline(b'30')
p.sendline(b'123456')
p.sendline(b'5')
p.interactive()
#0xffc34930
#0xffc348dc
