# from pwn import *
#
# p = process('./game2')
# elf = process('./game2')
# # gdb.attach(p)
# payload = b'p'
# p.sendline(payload)
# gdb.attach(p)
# # payload = b'd' + b's'
# # gdb.attach(p)
# # p.sendline(payload)
# p.interactive()
import base64
import os
import socket
ip = 'picoctf.org'
response = os.system("ping -c 1 " + ip)
#saving ping details to a variable
host_info = socket.gethostbyaddr(ip)
#getting IP from a domaine
host_info_to_str = str(host_info[2])
host_info = base64.b64encode(host_info_to_str.encode('ascii'))
print("Hello, this is a part of information gathering",'Host: ', host_info)