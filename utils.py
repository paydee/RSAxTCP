def ceil_div(a, b):
    q, r = divmod(a, b)
    if r:
        q += 1
    return q


def byte_size(n):
    if n == 0:
        return 1
    return ceil_div(n.bit_length(), 8)
