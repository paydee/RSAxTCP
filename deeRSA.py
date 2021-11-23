from random import choice, seed
from subprocess import run, PIPE
import re
import os
from utils import byte_size, ceil_div, urandom, int_size

E = 65537
FORMAT = "utf-8"


def gen_seed(target_len):
    """ Gen the first prime candidate to iterating
    like the instruction in the project

    :param target_len: number of decimal digits in prime
    :return: a candidate for prime with target_length number of decimal digits
    """
    seed()
    digits = ''
    for i in range(target_len):
        if i == 0: digits += choice('123456789')
        if i == target_len - 1: digits += choice('13579')
        digits += choice('0123456789')
        i += 1
    return digits


def is_prime(n):
    """ Check if a number is prime using openssl

    :param n: the number to check primeness
    :return: True if n is prime, False if otherwise
    """
    command = f"openssl prime {n}"
    r = run(command, shell=True, stdout=PIPE)
    result = str(r.stdout)
    if re.search(r"not prime", result):
        return False
    else:
        return True


def gen_prime(length):
    """Gen prime as in project's instruction

    :param length: number of digits of the prime generated
    :return: a prime in length decimal digits
    """
    init_seed = gen_seed(length)
    candidate = int(init_seed)
    if len(init_seed) <= 2:
        while not is_prime(candidate):
            init_seed = gen_seed(length)
            candidate = int(init_seed)
    while not is_prime(candidate):
        init_seed = init_seed[1:- 1]
        leading_zeros = 0
        while init_seed[leading_zeros] == '0':
            leading_zeros += 1
        init_seed = init_seed[leading_zeros:]
        for i in range(length - len(init_seed) - 1):
            init_seed += choice('1234567890')
        init_seed += choice('1379')
        candidate = int(init_seed)

    return candidate


def eea(a, b):
    """ Extended Euclid Algorithm
    :return: gcd(a, b), x, y where ax+by = gcd(a,b)
    """
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def inverse(a, m):
    """ Find inverse of a in modulo m
    :return: inverse of a in modulo m
    """
    gcd, x, y = eea(a, m)
    if gcd != 1:
        return None
    return x % m


def powmod(x, y, n):
    """ Power in modulo n
    :return: x**y mod(n)
    """
    result = 1
    while y > 0:
        if y & 1 > 0:
            result = (result * x) % n
        y >>= 1
        x = (x * x) % n
    return result


def gen_key(length):
    """Gen RSA public key in number of length decimal digits
    :return: modulo n with length number of decimal digits, public exponent d
    """
    p = gen_prime(ceil_div(length, 2))
    needlen = length - ceil_div(length, 2)
    q = gen_prime(needlen)
    n = p * q
    while len(str(n)) != length:
        q = gen_prime(needlen)
        n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(E, phi)
    return n, d


# OS2IP
def bytes_to_int(mess):
    """Converts an octet string to a nonnegative integer, similar to OS2IP pkcv1.5
     RFC 3447

    :param mess: bytes string message
    :return: integer representation of mess
    """
    mess_len = len(mess)
    mess = mess[::-1]
    int_mess = 0
    for i in range(mess_len):
        int_mess += mess[i] * 256 ** i
    return int_mess


def int_to_bytes(int_mess, target_len):
    """converts a nonnegative integer to an octet string of a specified length
    I2OSP - pkcv1.5 RFC 3447

    :param int_mess: integer representation  of mess
    :param target_len: size in bytes of byte representation of int_mess
    :return: bytes string representation in target_length of int_mess
    """
    if int_mess > 256 ** target_len: raise ValueError("Integer too large")
    digits = []
    while int_mess:
        digits.append(int(int_mess % 256))
        int_mess //= 256
    for i in range(target_len - len(digits)):
        digits.append(0)
    return bytes(digits[::-1])


def pad_for_encryption(mess, target_len):
    """PKCv1.5 padding scheme.
    Padding with size at least 8 bytes of random bytes
    Padded message has form b'\x00\x02',padding,b'\x00',mess

    :param mess: bytes string mess to pass
    :param target_len: length of padded mess
    :return: Padded mess in target_size
    """
    maxlen = target_len - 11
    messlen = len(mess)
    if messlen > maxlen:
        raise OverflowError("Message too large!")
    padlen = target_len - messlen - 3
    padding = b''
    while len(padding) < padlen:
        needlen = padlen - len(padding)
        new_padding = urandom(needlen)
        new_padding = new_padding.replace(b'\x00', b'')
        padding = padding + new_padding[:needlen]
    return b''.join([b'\x00\x02',
                     padding,
                     b'\x00',
                     mess])


def encrypt(mess, n, e):
    """RSA encryption a message

    :param mess: bytes string mess
    :param n: modulo key
    :param e: private exponent key
    :return: Encrypted message with RSA in bytes string
    """
    keylen = byte_size(n)
    mess = pad_for_encryption(mess, keylen)
    m_int = bytes_to_int(mess)
    c_int = powmod(m_int, e, n)
    return int_to_bytes(c_int, keylen)


def decrypt(cipher, n, d):
    """Decrypt message with RSA

    :param cipher: bytes string of cipher text
    :param n: modulo key
    :param d: public exponent key
    :return: Decrypted message with RSA in bytes string
    """
    keylen = byte_size(n)
    c_int = bytes_to_int(cipher)
    m_int = powmod(c_int, d, n)
    clear_mess = int_to_bytes(m_int, keylen)
    if len(cipher) > keylen:
        raise ValueError("Decryption failed")
    sep_idx = clear_mess.find(b'\x00', 2)
    return clear_mess[sep_idx + 1:]

