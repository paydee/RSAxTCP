from random import getrandbits, seed
from subprocess import run, PIPE
import re
from math import log

E = 65537
FORMAT = "utf-8"


def gen_candidate(length):
    seed()
    p = getrandbits(length)
    p |= (1 << length - 1) | 1
    print(int(log(p, 256) + 1))
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


def gen_rsa_para(length):
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
def string_to_int(mess):
    b_mess = bytes(mess, FORMAT)
    len_mess = len(b_mess)
    b_mess = b_mess[::-1]  # reverse mess
    c_mess = 0
    for i in range(len_mess):
        c_mess += b_mess[i] * 256 ** i
    return c_mess


# converts a nonnegative integer to an octet string of a specified length I2OSP / RFC 3447
def int_to_string(cipher, mlen):
    if cipher >= 256 ** mlen:
        raise ValueError("integer too large")
    digits = []

    while cipher:
        digits.append(int(cipher % 256))
        cipher //= 256
    for i in range(mlen - len(digits)):
        digits.append(0)
    mess = bytes(digits[::-1]).decode(FORMAT)
    return mess


# PKCS1-v1_5 padding scheme
# def pad_for_encryption(mess, target_len):


def encrypt(mess, n, e):
    m_int = string_to_int(mess)
    c_int = powmod(mess, e, n)
    return int_to_string(c_int, len(mess))


def decrypt(mess, n, d):
    m_int = string_to_int(mess)
    c_int = powmod(mess, d, n)
    return int_to_string(c_int, len(mess))


if __name__ == '__main__':
    # s, t = gen_prime(1024)
    n, d = gen_rsa_para(1024)
    print(n)
    print(int(log(n, 256)) + 1)

    # mess = "hello dkhfkhsdof skfsdkh sdkhlf"
    # c = string_to_int(mess)
    # m = int_to_string(c, 31)
    # print(c)
    # print(m)
    # print(d)
    # print(f"{q} is prime after {c} times try")
