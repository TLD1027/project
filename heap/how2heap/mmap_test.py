from pwn import *

p = process('./mmap')

gdb.attach(p)

p.interactive()