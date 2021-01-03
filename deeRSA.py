from random import getrandbits, seed
from subprocess import run, PIPE
import re
import os
from utils import byte_size, ceil_div
from math import log

E = 65537
FORMAT = "utf-8"


def gen_candidate(length):
    seed()
    p = getrandbits(length)
    p |= (1 << length - 1) | 1
    return p


def is_prime(n):
    command = f"openssl prime {n}"
    r = run(command, shell=True, stdout=PIPE)
    result = str(r.stdout)
    if re.search(r"not prime", result):
        return 0
    else:
        return 1


def gen_prime(length):
    p = gen_candidate(length)
    while not is_prime(p):
        p = gen_candidate(length)
    return p


def eea(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def inverse(a, m):
    gcd, x, y = eea(a, m)
    if gcd != 1:
        return None
    return x % m


def powmod(x, y, n):
    result = 1
    while y > 0:
        if y & 1 > 0:
            result = (result * x) % n
        y >>= 1
        x = (x * x) % n
    return result


def gen_key(length):
    p = gen_prime(length // 2)
    q = gen_prime(length // 2)
    while p == q:
        q = gen_prime(length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(E, phi)
    return n, d


# TODO: format mess OS2IP IP2OS
# OS2IP converts an octet string to a nonnegative integer RFC 3447
def bytes_to_int(mess):
    return int.from_bytes(mess, 'big', signed=False)


# converts a nonnegative integer to an octet string of a specified length I2OSP / RFC 3447
def int_to_bytes(cipher, target_len):
    needlen = max(1, cipher.bit_length() // 8)
    if target_len > 0:
        return cipher.to_bytes(target_len, 'big')
    return cipher.to_bytes(needlen, 'big')


# PKCS1-v1_5 padding scheme
def pad_for_encryption(mess, target_len):
    maxlen = target_len - 11
    messlen = len(mess)
    if messlen > maxlen:
        raise OverflowError("Message too large!")
    padlen = target_len - messlen - 3
    padding = b''
    while len(padding) < padlen:
        needlen = padlen - len(padding)
        new_padding = os.urandom(needlen + 5)
        new_padding = new_padding.replace(b'\x00', b'')
        padding = padding + new_padding[:needlen]
    return b''.join([b'\x00\x02',
                     padding,
                     b'\x00',
                     mess])


def encrypt(mess, n, e):
    keylen = byte_size(n)
    pad_for_encryption(mess, keylen)
    m_int = bytes_to_int(mess)
    c_int = powmod(m_int, e, n)
    return int_to_bytes(c_int, keylen)


def decrypt(cipher, n, d):
    keylen = byte_size(n)
    i_cipher = bytes_to_int(cipher)
    c_int = powmod(i_cipher, d, n)
    clear_mess = int_to_bytes(c_int, keylen)
    if len(cipher) > keylen:
        raise ValueError("Decryption failed")
    sep_idx = clear_mess.find(b'\x00', 2)
    return clear_mess[sep_idx + 1:]


if __name__ == '__main__':
    # s, t = gen_prime(1024)
    # n, d = gen_rsa_para(1024)
    # mess = b'ggggggggg'
    # c = encrypt(mess, n, E)
    # m = decrypt(c, n, d)
    # print(m.decode(FORMAT))
    x = 100999
    t = x.to_bytes(byte_size(x), 'big')
    print(t)


    # mess = "hello dkhfkhsdof skfsdkh sdkhlf"
    # c = string_to_int(mess)
    # m = int_to_string(c, 31)
    # print(c)
    # print(m)
    # print(d)
    # print(f"{q} is prime after {c} times try")
