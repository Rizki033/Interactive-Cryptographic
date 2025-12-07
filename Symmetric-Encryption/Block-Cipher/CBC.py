#!/usr/bin/env python3
"""
cbc_mode_generic.py
Implementation générique du mode CBC (Cipher Block Chaining).
Nécessite une primitive de chiffrement de bloc (encrypt_block/decrypt_block).
Utilise PKCS#7 pour le padding.
"""

from typing import Callable
import os

# -------------------------
# Padding PKCS#7 (same functions as ECB)
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
# CBC (generic)
# -------------------------
def encrypt_cbc(block_encrypt: Callable[[bytes], bytes], block_size: int, plaintext: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using CBC (Cipher Block Chaining) mode.
    
    CBC mode chains plaintext blocks together by XORing each plaintext block with the
    previous ciphertext block before encryption. This creates dependencies between blocks,
    so identical plaintext blocks produce different ciphertext blocks (unlike ECB).
    
    Process:
    1. Pad plaintext to a multiple of block_size using PKCS#7
    2. Generate random IV if not provided
    3. For each plaintext block:
       a. XOR the block with the previous ciphertext block (or IV for first block)
       b. Encrypt the XORed block
       c. The ciphertext block becomes prev for the next iteration
    4. Concatenate all ciphertext blocks
    
    Properties:
    - Each plaintext block depends on all previous blocks
    - Identical plaintext blocks produce different ciphertext blocks
    - IV must be random and unique for each encryption with same key
    - Padding is required (PKCS#7 used here)
    - Cannot parallelize encryption (sequential dependency)
    - Can parallelize decryption (only needs previous ciphertext block)
    
    Args:
        block_encrypt: Callable that encrypts a single block (bytes) and returns ciphertext (bytes)
        block_size: Size of each block in bytes (typically 16 for AES, 8 for DES)
        plaintext: Data to encrypt (bytes of any length)
        iv: Initialization Vector (bytes of block_size). If None, random IV is generated.
    
    Returns:
        Tuple of (iv, ciphertext):
        - iv: The IV used (useful if it was randomly generated)
        - ciphertext: Encrypted data (length is multiple of block_size due to padding)
    
    Raises:
        ValueError: If IV length doesn't match block_size
    """
    if iv is None:
        iv = os.urandom(block_size)
    if len(iv) != block_size:
        raise ValueError("IV length must equal block size")

    # Pad plaintext to multiple of block_size
    data = pkcs7_pad(plaintext, block_size)
    ciphertext_blocks = []
    prev = iv  # Start with IV as the previous "ciphertext block"
    
    # Process each plaintext block
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]  # Current plaintext block
        
        # XOR current block with previous ciphertext block (or IV for first block)
        xored = bytes([b ^ p for b, p in zip(block, prev)])
        
        # Encrypt the XORed block
        cblock = block_encrypt(xored)
        ciphertext_blocks.append(cblock)
        
        # This ciphertext block becomes the prev for the next iteration
        prev = cblock
    
    return iv, b"".join(ciphertext_blocks)

def decrypt_cbc(block_decrypt: Callable[[bytes], bytes], block_size: int, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using CBC (Cipher Block Chaining) mode.
    
    CBC decryption reverses the encryption process:
    1. For each ciphertext block:
       a. Decrypt the ciphertext block
       b. XOR the decrypted block with the previous ciphertext block (or IV for first block)
       c. The result is the plaintext block
       d. Save current ciphertext block as prev for next iteration
    2. Remove PKCS#7 padding
    
    Properties:
    - Decryption can be parallelized (each block only needs previous ciphertext)
    - IV must be the same IV used during encryption
    - Ciphertext length must be a multiple of block_size
    - Padding is automatically removed
    
    Args:
        block_decrypt: Callable that decrypts a single block (ciphertext bytes) and returns plaintext (bytes)
        block_size: Size of cipher blocks in bytes (must match encryption block_size)
        iv: Initialization Vector (bytes of block_size) - must be same as encryption IV
        ciphertext: Data to decrypt (bytes), must have length = multiple of block_size
    
    Returns:
        Decrypted plaintext (bytes) with PKCS#7 padding removed
    
    Raises:
        ValueError: If IV or ciphertext length is invalid
    """
    if len(iv) != block_size:
        raise ValueError("IV length must equal block size")
    if len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext length must be multiple of block size")

    plaintext_blocks = []
    prev = iv  # Start with IV as the previous "ciphertext block"
    
    # Process each ciphertext block
    for i in range(0, len(ciphertext), block_size):
        cblock = ciphertext[i:i+block_size]  # Current ciphertext block
        
        # Decrypt the ciphertext block
        xored = block_decrypt(cblock)
        
        # XOR decrypted block with previous ciphertext block (or IV for first block)
        pblock = bytes([x ^ p for x, p in zip(xored, prev)])
        plaintext_blocks.append(pblock)
        
        # Current ciphertext block becomes prev for next iteration
        prev = cblock
    
    # Combine all plaintext blocks and remove padding
    padded = b"".join(plaintext_blocks)
    return pkcs7_unpad(padded, block_size)

# -------------------------
# DummyBlockCipher (example)
# -------------------------
class DummyBlockCipher:
    """
    Dummy (non-cryptographic) block cipher for educational/testing purposes only.
    
    WARNING: This is NOT secure for real encryption. It's designed only to demonstrate
    how block cipher primitives work with CBC mode.
    
    Implementation: Simple XOR with constant 0x55 on each byte.
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
        Encrypt a single block by XORing each byte with 0x55.
        
        Args:
            block: Plaintext block (must be exactly block_size bytes)
        
        Returns:
            Ciphertext block (bytes)
        
        Raises:
            ValueError: If block length doesn't match block_size
        """
        if len(block) != self.block_size:
            raise ValueError("Block length mismatch")
        return bytes([b ^ 0x55 for b in block])

    def decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt a single block by XORing each byte with 0x55.
        
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
        return bytes([b ^ 0x55 for b in block])

# -------------------------
# Example usage
# -------------------------
if __name__ == "__main__":
    # Initialize cipher with 16-byte blocks (matching AES block size)
    block_size = 16
    cipher = DummyBlockCipher(block_size=block_size)

    # Original plaintext message
    plaintext = b"Un message confidentiel pour CBC mode."
    print("Plaintext:", plaintext)

    # Encrypt using CBC mode
    # encrypt_cbc returns both the IV (for decryption) and the ciphertext
    iv, ct = encrypt_cbc(cipher.encrypt_block, block_size, plaintext)
    print("IV (hex):", iv.hex())
    print("Ciphertext (hex):", ct.hex())

    # Decrypt using CBC mode with same IV and ciphertext
    # The recovered plaintext should exactly match the original
    recovered = decrypt_cbc(cipher.decrypt_block, block_size, iv, ct)
    print("Recovered plaintext:", recovered)
    print("Match:", recovered == plaintext)  # Should be True
