from pwn import *


def run():
    p = process('./redpacket')
    # p = remote('node4.buuoj.cn', 25747)
    lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')

    def choice(id_):
        p.recvuntil(b'Your input:')
        p.sendline(id_)

    def add(id_, size_, mess):
        choice(b'1')
        p.recvuntil(b':')
        p.sendline(id_)
        p.recvuntil(b':')
        p.sendline(size_)
        p.recvuntil(b':')
        p.sendline(mess)

    def delete(id_):
        choice(b'2')
        p.recvuntil(b':')
        p.sendline(id_)

    def edit(id_, mess):
        choice(b'3')
        p.recvuntil(b':')
        p.sendline(id_)
        p.recvuntil(b':')
        p.sendline(mess)

    def show(id_):
        choice(b'4')
        p.recvuntil(b':')
        p.sendline(id_)

    add(b'0', b'1', b'a' * 9)
    # add(b'1', b'1', b'aaa')
    gdb.attach(p)
    p.interactive()

if __name__ == '__main__':
    run()
