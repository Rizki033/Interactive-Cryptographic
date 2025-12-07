#!/usr/bin/env python3
"""
Implementation générique du mode ECB (Electronic Code Book).
Nécessite une primitive de chiffrement de bloc (encrypt_block/decrypt_block).
Utilise PKCS#7 pour le padding.
"""

from typing import Callable
import math

# -------------------------
# Padding PKCS#7
# -------------------------
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """
    Add PKCS#7 padding to data to make its length a multiple of block_size.
    
    PKCS#7 padding works by appending n bytes of value n to the data,
    where n is the number of bytes needed to reach the next block boundary.
    Example: if block_size=16 and data is 10 bytes, we add 6 bytes of value 0x06.
    
    Args:
        data: The input data (bytes) to pad
        block_size: The target block size in bytes (typically 16 for AES)
    
    Returns:
        Padded data as bytes, with length being a multiple of block_size
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """
    Remove PKCS#7 padding from padded data.
    
    This function verifies that:
    1. The data length is a multiple of block_size
    2. The padding length is valid (between 1 and block_size)
    3. The last N bytes all have the correct padding value
    
    Args:
        data: The padded data (bytes) to unpad
        block_size: The block size in bytes (must match the padding block size)
    
    Returns:
        Original unpadded data as bytes
    
    Raises:
        ValueError: If padding is invalid (malformed or incorrect format)
    """
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    
    pad_len = data[-1]
    
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]

# -------------------------
# ECB (générique)
# -------------------------
def encrypt_ecb(block_encrypt: Callable[[bytes], bytes], block_size: int, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using ECB (Electronic Code Book) mode.
    
    ECB mode divides plaintext into fixed-size blocks and encrypts each block
    independently using the same encryption function. This makes it fast but
    reveals patterns in the plaintext (identical plaintext blocks produce
    identical ciphertext blocks), so ECB is NOT recommended for production use.
    
    Process:
    1. Pad plaintext to a multiple of block_size using PKCS#7
    2. Split padded data into blocks
    3. Encrypt each block independently
    4. Concatenate all encrypted blocks
    
    Args:
        block_encrypt: Callable that encrypts a single block (bytes) and returns ciphertext (bytes)
        block_size: Size of each block in bytes (typically 16 for AES, 8 for DES)
        plaintext: Data to encrypt (bytes)
    
    Returns:
        Encrypted ciphertext (bytes) with length = multiple of block_size
    """
    data = pkcs7_pad(plaintext, block_size)
    ciphertext_blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        cblock = block_encrypt(block)
        ciphertext_blocks.append(cblock)
    return b"".join(ciphertext_blocks)

def decrypt_ecb(block_decrypt: Callable[[bytes], bytes], block_size: int, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using ECB (Electronic Code Book) mode.
    
    ECB decryption reverses the encryption process:
    1. Verify ciphertext length is a multiple of block_size
    2. Split ciphertext into blocks
    3. Decrypt each block independently using the same decryption function
    4. Concatenate all decrypted blocks
    5. Remove PKCS#7 padding
    
    Args:
        block_decrypt: Callable that decrypts a single block (ciphertext bytes) and returns plaintext (bytes)
        block_size: Size of each block in bytes (must match encryption block_size)
        ciphertext: Data to decrypt (bytes), must have length = multiple of block_size
    
    Returns:
        Decrypted plaintext (bytes) with PKCS#7 padding removed
    
    Raises:
        ValueError: If ciphertext length is not a multiple of block_size
    """
    if len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    plaintext_blocks = []
    for i in range(0, len(ciphertext), block_size):
        cblock = ciphertext[i:i+block_size]
        pblock = block_decrypt(cblock)
        plaintext_blocks.append(pblock)
    padded = b"".join(plaintext_blocks)
    return pkcs7_unpad(padded, block_size)

# -------------------------
# DummyBlockCipher (exemple)
# -------------------------
class DummyBlockCipher:
    """
    Dummy (non-cryptographic) block cipher for educational/testing purposes only.
    
    WARNING: This is NOT secure for real encryption. It's designed only to demonstrate
    how block cipher primitives work with ECB mode.
    
    Implementation: Simple XOR with constant 0xAA on each byte.
    Properties:
    - Deterministic: same input always produces same output
    - Reversible: XOR is its own inverse (f(f(x)) = x)
    - Weak: trivial to break, pattern analysis reveals everything
    
    Attributes:
        block_size: Size of each block in bytes (default: 16)
    """
    def __init__(self, block_size=16):
        """
        Initialize the dummy cipher.
        
        Args:
            block_size: Size in bytes (default 16 to match AES)
        """
        self.block_size = block_size

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypt a single block by XORing each byte with 0xAA.
        
        Args:
            block: Plaintext block (must be exactly block_size bytes)
        
        Returns:
            Ciphertext block (bytes)
        
        Raises:
            ValueError: If block length doesn't match block_size
        """
        if len(block) != self.block_size:
            raise ValueError("Block length mismatch")
        return bytes([b ^ 0xAA for b in block])

    def decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt a single block by XORing each byte with 0xAA.
        
        Note: This is the same operation as encrypt_block because XOR is symmetric
        (a XOR b XOR b = a). This is NOT typical for real ciphers!
        
        Args:
            block: Ciphertext block (must be exactly block_size bytes)
        
        Returns:
            Plaintext block (bytes)
        
        Raises:
            ValueError: If block length doesn't match block_size
        """
        if len(block) != self.block_size:
            raise ValueError("Block length mismatch")
        return bytes([b ^ 0xAA for b in block])

# -------------------------
# Exemple d'utilisation
# -------------------------
if __name__ == "__main__":
    # Initialize the dummy cipher with 16-byte blocks (matching AES block size)
    block_size = 16
    cipher = DummyBlockCipher(block_size=block_size)

    # Original plaintext message
    plaintext = b"Message secret pour ECB mode - longueur variable!"
    print("Plaintext:", plaintext)

    # Encrypt using ECB mode
    # encrypt_ecb will pad the plaintext and encrypt each block independently
    ct = encrypt_ecb(cipher.encrypt_block, block_size, plaintext)
    print("Ciphertext (hex):", ct.hex())

    # Decrypt using ECB mode
    # decrypt_ecb will decrypt each block and remove padding
    pt = decrypt_ecb(cipher.decrypt_block, block_size, ct)
    print("Recovered plaintext:", pt)
