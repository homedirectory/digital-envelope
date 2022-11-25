from math import ceil

def int_to_bigend(n: int) -> bytes:
    return n.to_bytes(ceil(n.bit_length() / 8), 'big')
