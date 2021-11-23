# Some supportive functions
import random
import math


FORMAT = 'utf-8'
HEADER = 64


def ceil_div(a, b):
    q, r = divmod(a, b)
    if r:
        q += 1
    return q


def bit_size(n: int):
    return len(bin(n)[2:])


def byte_size(n):
    if n == 0:
        return 1
    return ceil_div(bit_size(n), 8)


def urandom(target_length):
    return bytes([random.randint(0, 255) for _ in range(0, target_length)])


def int_size(bit_size: int):
    value = 2 ** bit_size
    return int(math.log(value, 10))


def bit_size_2_decimal_digit(n):
    return math.ceil((math.log(2**n, 10)))
