import random
import hashlib

import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import warnings
# dont warn about using CAST5
warnings.filterwarnings("ignore", category=cryptography.utils.CryptographyDeprecationWarning)

from rsa import RSAKey, rsa_encrypt, rsa_decrypt

CAST128_BLOCK_SIZE = 16
SESS_KEY_BITLEN = 128
SESS_KEY_LEN = SESS_KEY_BITLEN // 8
RSA_KEY_BITLEN = 1024
RSA_KEY_LEN = RSA_KEY_BITLEN // 8

# generates one-time session key for symmetric encryption
def gen_sesskey(bitlen: int) -> bytes:
    # make sure its big enough
    key = random.randrange(2**(bitlen//4), 2**bitlen)
    return key.to_bytes(bitlen//8, 'big')

def cast128_enc(plaintext: bytes, key: bytes):
    algo = algorithms.CAST5(key)
    # ECB is the simplest block mode, used by CAST5
    cipher = Cipher(algo, mode=modes.ECB())
    return cipher.encryptor().update(plaintext)

def cast128_dec(ciphertext: bytes, key: bytes):
    algo = algorithms.CAST5(key)
    # ECB is the simplest block mode, used by CAST5
    cipher = Cipher(algo, mode=modes.ECB())
    return cipher.decryptor().update(ciphertext)


class Envelope:
    def __init__(self, sesskey: bytes, data: bytes, signature: bytes):
        self.sesskey = sesskey # encrypted session key
        self.data = data       # ciphertext
        self.signature = signature # digital signature

    """
    pk - recipient's public key
    sk - sender's secret key
    """
    @staticmethod
    def create(plaintext: bytes, pk: RSAKey, sk: RSAKey):
        """
        Algorithm:
        1. generate symmetric session key
        2. encrypt session key with receiver's public key
        3. encrypt message with session key
        4. encrypt message hash with sender's private key to obtain digital signature
        5. form digital envelope
        """

        # 1. generate 128-bit session key
        sesskey = gen_sesskey(SESS_KEY_BITLEN)

        # 2. encrypt session key with public RSA key
        enc_sesskey = rsa_encrypt(sesskey, pk)

        # 3. encrypt plaintext with session key
        # add padding at the beginning if needed
        # later calculate hash from already padded message
        n = CAST128_BLOCK_SIZE - (len(plaintext) % CAST128_BLOCK_SIZE)
        plaintext = (b'\x00' * n) + plaintext
        ciphertext = cast128_enc(plaintext, sesskey)

        # 4. make signature
        #  4.1. calculate SHA1(plaintext)
        h = hashlib.sha1(plaintext).digest()
        #  4.2 encrypt hash with secret key
        signature = rsa_encrypt(h, sk);

        # 5. form envelope
        return Envelope(enc_sesskey, ciphertext, signature)

    @staticmethod
    def from_file(filename):
        with open(filename, 'rb') as f:
            # 1. encrypted session key (length of RSA key) 1024 bits = 128 bytes
            sesskey = f.read(RSA_KEY_LEN)
            assert len(sesskey) == RSA_KEY_LEN,\
                    f"Session key is too short: {len(sesskey)} < {SESS_KEY_LEN}"
            # 2. digital signature (length of RSA key) 1024 bits = 128 bytes
            signature = f.read(RSA_KEY_LEN)
            assert len(signature) == RSA_KEY_LEN,\
                    f"Signature is too short: {len(signature)} < {SIG_LEN}"
            # 3. encrypted message
            data = f.read()

            return Envelope(sesskey, data, signature)

    def save(self, filename):
        """
        File will have the following contents:
            encrypted session key
            digital signature
            encrypted message
        """
        with open(filename, 'wb') as f:
            # 1. encrypted session key
            f.write(self.sesskey)
            # 2. digital signature
            f.write(self.signature)
            # 3. encrypted message
            f.write(self.data)

"""
pk - sender's public key
sk - recipient's secret key
"""
def open_envelope(envlp: Envelope, pk: RSAKey, sk:RSAKey) -> bytes:
    """
    Algorithm:
        1. Decrypt session key with recipient's secret key
        2. Decrypt message with session key
        3. Decrypt signature with sender's public key
        4. Compare decrypted signature with message hash
    """
    # 1.
    sesskey = rsa_decrypt(envlp.sesskey, sk)
    # 2.
    plaintext = cast128_dec(envlp.data, sesskey)
    # 3.
    signature = rsa_decrypt(envlp.signature, pk)
    # 4.
    h = hashlib.sha1(plaintext).digest()
    if h != signature:
        raise Exception(f"""
        Could not verify signature. Digests differ.
        Signature      : {signature}
        Message hash   : {h}
        """)

    return plaintext


if __name__ == "__main__":
    from rsa import rsa_gen_keys

    # bob sends message to alice
    bob_pk, bob_sk = rsa_gen_keys(RSA_KEY_BITLEN)
    alice_pk, alice_sk = rsa_gen_keys(RSA_KEY_BITLEN)

    msg_bob = "Hello, Alice! It's Bob. Have you received this encrypted message? It might be padded with zeros at the beginning, though."
    envlp = Envelope.create(msg_bob.encode(), alice_pk, bob_sk)
    print("Bob sent an envelope to Alice with message:")
    print(msg_bob)

    print("-" * 40)
    
    msg_alice = open_envelope(envlp, bob_pk, alice_sk)
    # remove padding
    msg_alice = msg_alice.lstrip(b'\x00').decode()
    print("Alice received an envelope from Bob with message:")
    print(msg_alice)
    assert msg_bob == msg_alice
    
    # save to file
    envlp.save("/tmp/envelope")
