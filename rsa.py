from math import ceil
from enum import Enum
import random

from math_funcs import mod_mul_inv, lcm, gcd, rand_prime, randbytes
from utils import int_to_bigend

PAD_MSG_MIN_LEN = 12
MIN_PS_LEN = 8

class RSAKey:
    def __init__(self, modulus, exponent, ispub, size):
        self.modulus = modulus
        self.exponent = exponent
        self.ispub = ispub
        self.size = size

    def is_public(self):
        return self.ispub

    def is_secret(self):
        return not self.ispub

    def bytesize(self):
        return self.size // 8

    @staticmethod
    def create(ispub, keysize):
        return RSAKey(0, 0, bool(ispub), keysize)

    @staticmethod
    def create_pub(keysize):
        return RSAKey.create(True, keysize)

    @staticmethod
    def create_sec(keysize):
        return RSAKey.create(False, keysize)

    @staticmethod
    def from_file(filename):
        def saferead(f, n):
            b = f.read(n)
            assert len(b) == n, f"{len(b)} != {n}"
            return b

        with open(filename, 'rb') as f:
            # type of key: pub (1) or sec (0)
            b = saferead(f, 1)
            ispub = int.from_bytes(b, 'big')

            # key size
            b = saferead(f, 4)
            keysize = int.from_bytes(b, 'big')

            key = RSAKey.create(bool(ispub), keysize)

            kbs = key.bytesize()
            # modulus
            b = saferead(f, kbs)
            key.modulus = int.from_bytes(b, 'big')
            b = saferead(f, kbs)
            key.exponent = int.from_bytes(b, 'big')

            return key

    """
    Saves key to file in the following format:
        type of key
        key size
        modulus
        exponent
    where:
        attributes are NOT delimited by anything
        attribute are written as raw bytes

        type of key - is either 1 (pub) or 0 (sec)
        key size    - stored as a 4 byte integer (raw byte)
        modulus, exponent - raw bytes
    """
    def save(self, filename):
        with open(filename, 'wb') as f:
            # type of key
            keytype = 1 if self.ispub else 0
            f.write(keytype.to_bytes(1, 'big'))
            # key size (4 bytes long)
            f.write(self.size.to_bytes(4, 'big'))

            keysize_bytes = self.size // 8
            # modulus
            f.write(self.modulus.to_bytes(keysize_bytes, 'big'))
            # exponent
            f.write(self.exponent.to_bytes(keysize_bytes, 'big'))


"""
Generate public/secret key pair.
    keysize - key length in bits

Returns a tuple (public key, secret key)
"""
def rsa_gen_keys(keysize: int) -> tuple:
    print(f"Generating RSA key pair with keysize {keysize}")

    """
    Algorithm:
    1. choose 2 large primes p & q
     bit length of p and q combined should be <= key size
     to make factoring harder p and q should differ in length slightly
    2. n = pq, used for the modulus in both pub and sec keys, its max length is == key size
    3. compute lambda = lcm(p-1,q-1)
    4. choose e s.t. 1 < e < lambda, gcd(e, lambda) = 1 (coprime)
     e is a part of the public key
    5. d = e^-1 (mod lambda), modular multiplicative inverse of e mod lambda
     d is a part of the secret key
    """
    _MIN_P_Q = 1
    _MAX_P_Q = 2**(keysize//2)

    pk = RSAKey.create_pub(keysize)
    sk = RSAKey.create_sec(keysize)

    # 1. choose 2 large primes p & q
    # to obtain an n-bit number by multiplying 2 other numbers (a & b)
    # without a risk of overflowing n bits
    # a & b should be max n/2 bits in length
    p = rand_prime(_min=_MIN_P_Q, _max=_MAX_P_Q)
    q = rand_prime(_min=_MIN_P_Q, _max=_MAX_P_Q)
    #print(f"p = {p}");
    #print(f"q = {q}");

    # 2. n = pq
    n = p * q
    #print(f"n = {n}");

    pk.modulus = n
    sk.modulus = n

    # 3. lcm(p-1, q-1)
    lam = lcm(p-1, q-1)
    #print(f"lcm(p-1, q-1) = {lam}");

    # 4. choose e (pub key) s.t. 1 < e < lambda AND gcd(e, lambda) == 1
    e = random.randrange(2, lam-1)
    while gcd(e, lam) != 1:
        e = random.randrange(2, lam-1)
    
    #print(f"e = {e}");
    pk.exponent = e

    # 5. compute d (sec key)
    d = mod_mul_inv(e, lam)
    sk.exponent = d
    #print(f"d = {d}");

    print("RSA keys were generated")

    return (pk, sk)

class BlockType(Enum):
    ENC_SEC = 0x01
    ENC_PUB = 0x02
    DEC_SEC = 0x02
    DEC_PUB = 0x01

    # enc - indicates whether this block will be used for encryption or decryption
    @staticmethod
    def from_key(key: RSAKey, enc: bool):
        if enc:
            return BlockType.ENC_PUB if key.is_public() else BlockType.ENC_SEC
        else:
            return BlockType.DEC_PUB if key.is_public() else BlockType.DEC_SEC

    def to_bytes(self):
        return int.to_bytes(self.value, 1, 'big')

    @staticmethod
    def verify_byte(bt, _byte):
        if bt == 0x01:
            return _byte == 0xff
        elif bt == 0x02:
            return _byte != 0x00
        raise Exception(f"Unknown BlockType: {bt}")

"""
Creates a padded message from data to be encrypted.
Key is needed to determine the padding scheme and know its length
"""
def pad(data: bytes, key: RSAKey) -> bytes:
    k = key.bytesize()
    n = len(data)
    assert n < k - 11, \
            f"Data length must be < (k - 11). k={k}, len(data)={n}"
    ps_len = k - 3 - n
    assert ps_len >= MIN_PS_LEN, f"PS length must be >= f{MIN_PS_LEN}, but was {ps_len}"

    # 00 || BlockType || PS || 00 || D (orig msg)
    padded = b'\x00'
    # BlockType
    bt = BlockType.from_key(key, enc=True)
    padded += bt.to_bytes()
    # PS is formed based on BlockType
    # ENC_SEC - all 0xff
    # ENC_PUB - non-zero random bytes
    if bt == BlockType.ENC_SEC:
        padded += b'\xff' * ps_len
    elif bt == BlockType.ENC_PUB:
        # generate ps_len random non-zero bytes
        padded += randbytes(ps_len)
    else:
        raise Exception(f"Invalid block type for padding: {bt.name}")
    # 00
    padded += b'\x00'
    # D
    padded += data

    return padded

"""
Reverses the padding scheme applied to data, recovering the original message.
Padding scheme is based on the BlockType that depends on type of key.
"""
def unpad(data: bytes, key: RSAKey) -> bytes:
    datalen = len(data)
    assert datalen >= PAD_MSG_MIN_LEN,\
            f"Padded message is too short: f{datalen} < f{PAD_MSG_MIN_LEN}"

    # 00 || BT || PS || 00 || D (orig msg)

    # 00
    i = 0
    assert data[i] == 0, f"Expected 0x00 1st byte, got {data[i]}"
    i+=1
    # BT
    bt = data[i]
    i+=1
    # PS || 00
    # read until 00 is found
    ps = bytes()
    while (data[i] != 0 and i < datalen):
        # verify format of PS block
        assert BlockType.verify_byte(bt, data[i]),\
                f"Incorrect byte in PS block. BlockType={bt.value}, byte={data[i]}"
        ps += data[i:i+1]
        i+=1
    assert i < datalen, f"PS block exceeds message length"
    assert i-1 >= MIN_PS_LEN, f"PS block too short: {i-1} < {MIN_PS_LEN}"
    # D
    i+=1
    return data[i:]


# RSA encryption
def rsa_encrypt(plaintext: bytes, key: RSAKey) -> bytes:
    padded = pad(plaintext, key)
    #print(padded)
    m = int.from_bytes(padded, 'big')
    assert m < key.modulus, f"m = {m}"
    
    # compute ciphertext
    # c = m**e (mod n)
    c = pow(m, key.exponent, mod=key.modulus)
    
    return c.to_bytes(key.bytesize(), 'big')

# RSA decryption
def rsa_decrypt(ciphertext: bytes, key: RSAKey) -> bytes:
    # convert ciphertext to a number
    ciphlen = len(ciphertext)
    assert ciphlen == key.bytesize(),\
            f"Ciphertext length should be == to modulus length ({key.bytesize()}, but was {ciphlen}"
    c = int.from_bytes(ciphertext, 'big')
    # c^d = m (mod n)
    m = pow(c, key.exponent, mod=key.modulus)
    m_bytes = m.to_bytes(len(ciphertext), 'big')

    # reverse padding scheme
    plaintext = unpad(m_bytes, key) 
    
    return plaintext


if __name__ == "__main__":
    pk, sk = rsa_gen_keys(1024)

    # test pad & unpad
    #msg = "hello world its me"
    #padded = pad(msg.encode(), keys[0])
    #unpadded = unpad(padded, keys[1])
    
    # test encryption with pub key & decryption with sec key
    for msg in ["hello world it's me", "  and another message here "]:
        cipher = rsa_encrypt(msg.encode(), pk)
        orig = rsa_decrypt(cipher, sk)
        assert msg.encode() == orig

    # test encryption with sec key & decryption with pub key
    for msg in ["hello world it's me", "  and another message here "]:
        cipher = rsa_encrypt(msg.encode(), sk)
        orig = rsa_decrypt(cipher, pk)
        assert msg.encode() == orig
