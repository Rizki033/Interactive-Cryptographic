from typing import Callable
from Crypto.Util.Padding import pad, unpad

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    return pad(data, block_size)

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    return unpad(data, block_size)

# -------------------------
# ECB Mode
# -------------------------

def encrypt_ecb(block_encrypt: Callable[[bytes], bytes], block_size: int, plaintext: bytes) -> bytes:
    data = pkcs7_pad(plaintext, block_size)
    return b"".join(block_encrypt(data[i:i+block_size]) for i in range(0, len(data), block_size))

def decrypt_ecb(block_decrypt: Callable[[bytes], bytes], block_size: int, ciphertext: bytes) -> bytes:
    data = b"".join(block_decrypt(ciphertext[i:i+block_size]) for i in range(0, len(ciphertext), block_size))
    return pkcs7_unpad(data, block_size)

# -------------------------
# CBC Mode
# -------------------------
def encrypt_cbc(block_encrypt: Callable[[bytes], bytes], block_size: int, plaintext: bytes, iv: bytes) -> bytes:
    data = pkcs7_pad(plaintext, block_size)
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        cblock = block_encrypt(xored)
        ciphertext += cblock
        prev_block = cblock
    return ciphertext

def decrypt_cbc(block_decrypt: Callable[[bytes], bytes], block_size: int, ciphertext: bytes, iv: bytes) -> bytes:
    plaintext = b""
    prev_block = iv
    for i in range(0, len(ciphertext), block_size):
        cblock = ciphertext[i:i+block_size]
        xored = block_decrypt(cblock)
        block = bytes(a ^ b for a, b in zip(xored, prev_block))
        plaintext += block
        prev_block = cblock
    return pkcs7_unpad(plaintext, block_size)

# -------------------------
# CFB Mode
# -------------------------

def encrypt_cfb(block_encrypt: Callable[[bytes], bytes], block_size: int, plaintext: bytes, iv: bytes) -> bytes:
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        enc = block_encrypt(prev_block)
        cblock = bytes(a ^ b for a, b in zip(block, enc[:len(block)]))
        ciphertext += cblock
        prev_block = cblock
    return ciphertext

def decrypt_cfb(block_encrypt: Callable[[bytes], bytes], block_size: int, ciphertext: bytes, iv: bytes) -> bytes:
    plaintext = b""
    prev_block = iv
    for i in range(0, len(ciphertext), block_size):
        cblock = ciphertext[i:i+block_size]
        enc = block_encrypt(prev_block)
        block = bytes(a ^ b for a, b in zip(cblock, enc[:len(cblock)]))
        plaintext += block
        prev_block = cblock
    return plaintext
