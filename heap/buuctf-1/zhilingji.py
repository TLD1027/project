from pwn import *


def ret(n1, n2, n3, n4):
    return u32((p8(n1) + p8(n2) + p8(n3) + p8(n4)))


def MOV(n1, n3):
    return ret(n1, 0, n3, 0x10)


def ZERO(n3):
    return ret(0, 0, n3, 0x20)


def READ(n1, n3):
    return ret(n1, 0, n3, 0x30)


def WRITE(n1, n3):
    return ret(n1, 0, n3, 0x40)


def PUSH(n3):
    return ret(0, 0, n3, 0x50)


def POP(n3):
    return ret(0, 0, n3, 0x60)


def ADD(n1, n2, n3):
    return ret(n1, n2, n3, 0x70)


def SUB(n1, n2, n3):
    return ret(n1, n2, n3, 0x80)


def AND(n1, n2, n3):
    return ret(n1, n2, n3, 0x90)


def XOR(n1, n2, n3):
    return ret(n1, n2, n3, 0xa0)


def OR(n1, n2, n3):
    return ret(n1, n2, n3, 0xb0)


def SHR(n1, n2, n3):
    return ret(n1, n2, n3, 0xc0)


def SHL(n1, n2, n3):
    return ret(n1, n2, n3, 0xd0)


def QUIT():
    return ret(0, 0, 0, 0xe0)