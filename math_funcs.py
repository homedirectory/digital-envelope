import math
import random

def mod_mul_inv(a, mod):
    return pow(a, -1, mod=mod)
    #r0 = a
    #r1 = mod
    #s0 = 1
    #s1 = 0
    #t0 = 0
    #t1 = 1
    #q = 0

    #def round(q, r0, r1, s0, s1, t0, t1):
    #    q = r0 / r1
    #    _r = r1
    #    r1 = r0 - (r1*q)
    #    r0 = _r

    #    _s = s1
    #    s1 = s0 - (q*s1)
    #    s0 = _s

    #    _t = t1
    #    t1 = t0 - (q*t1)
    #    t0 = _t

    #    return (q, r0, r1, s0, s1, t0, t1)

    #q, r0, r1, s0, s1, t0, t1 = round(q, r0, r1, s0, s1, t0, t1)
    #while (r1 > 0):
    #    q, r0, r1, s0, s1, t0, t1 = round(q, r0, r1, s0, s1, t0, t1)

    #return s0

def gcd(a, b):
    return math.gcd(a, b)

def lcm(a, b):
    return math.lcm(a, b)

def is_prime(n):
    return fermat_prime_test(n)

"""
n - number to test for primality
k - number of times to test
"""
def fermat_prime_test(n, k=10):
    if (n > 1 and n <= 3):
        return True
    elif (n <= 1):
        return False
    else:
        """
        Fermat primality test
        1. randomly choose a that is coprime to n ( 1 < a < n-1)
        2. calculate r = a**(n-1) mod n 
        3. r == 1 ? probably prime : not prime
        """
        for _ in range(k):
            a = random.randrange(2, n-1)
            r = pow(a, n-1, mod=n)
            if r != 1:
                return False

        return True

def rand_prime(_min=0, _max=0):
    p = random.randrange(_min, _max)
    while not fermat_prime_test(p, k=10):
        p = random.randrange(_min, _max)

    return p

# generate n random non-zero bytes
def randbytes(n):
    b = bytes()
    for _ in range(n):
        # NOTE this is slow
        r = random.randbytes(1)
        while r[0] == 0:
            r = random.randbytes(1)
        b += r

    return b
