#!/usr/bin/env python3
"""
cfb_mode_generic.py
Implementation générique du mode CFB (Cipher Feedback).
Nécessite une primitive de chiffrement de bloc (encrypt_block/decrypt_block).
CFB n'exige pas de padding et peut fonctionner en segments d'octets.
Ici on implémente CFB en segment = block_size octets (full-block CFB).
"""

from typing import Callable
import os

# -------------------------
# CFB (générique) - full-block feedback
# -------------------------
def encrypt_cfb(block_encrypt: Callable[[bytes], bytes], block_size: int, plaintext: bytes, iv: bytes = None) -> (bytes, bytes):
    """
    Encrypt plaintext using CFB (Cipher Feedback) mode - full-block variant.
    
    CFB mode is a stream cipher mode that turns a block cipher into a self-synchronizing
    stream cipher. It does NOT require padding, making it suitable for arbitrary-length data.
    
    Process:
    1. If no IV is provided, generate a random one of block_size bytes
    2. For each segment of plaintext (up to block_size bytes):
       a. Encrypt the previous ciphertext block (or IV for first block)
       b. Use only the first len(segment) bytes of keystream
       c. XOR plaintext segment with keystream to produce ciphertext segment
       d. The ciphertext segment becomes the input to the next block cipher call
    
    Properties:
    - No padding required: works with any length data
    - Self-synchronizing: bit errors don't propagate beyond one block
    - IV must be random and unique for each encryption with same key
    - Only encrypt_block is needed (no decrypt_block required)
    
    Args:
        block_encrypt: Callable that encrypts a block and returns keystream (bytes of block_size)
        block_size: Size of cipher blocks in bytes (typically 16 for AES)
        plaintext: Data to encrypt (bytes of any length)
        iv: Initialization Vector (bytes of block_size). If None, random IV is generated.
    
    Returns:
        Tuple of (iv, ciphertext):
        - iv: The IV used (useful if it was randomly generated)
        - ciphertext: Encrypted data (same length as plaintext)
    
    Raises:
        ValueError: If IV length doesn't match block_size
    """
    # Generate random IV if not provided
    if iv is None:
        iv = os.urandom(block_size)
    
    # Validate IV length matches block size
    if len(iv) != block_size:
        raise ValueError("IV length must equal block size")

    ciphertext_blocks = []
    prev = iv  # Previous ciphertext block (or IV for first iteration)
    
    # Process plaintext in segments of up to block_size bytes
    # Note: CFB mode works with ANY length data, not just multiples of block_size
    for i in range(0, len(plaintext), block_size):
        segment = plaintext[i:i+block_size]  # Current plaintext segment
        
        # Generate keystream by encrypting the previous ciphertext block
        # In CFB, we only use block_encrypt (no block_decrypt)
        keystream = block_encrypt(prev)
        
        # Truncate keystream to match segment length (for final partial block)
        ks_seg = keystream[:len(segment)]
        
        # XOR plaintext segment with keystream to produce ciphertext segment
        cseg = bytes([s ^ k for s, k in zip(segment, ks_seg)])
        ciphertext_blocks.append(cseg)
        
        # Update prev for next iteration (feedback mechanism)
        if len(cseg) == block_size:
            # Full block: use entire ciphertext block as next input
            prev = cseg
        else:
            # Partial block (final segment): shift register simulation
            # Replace beginning of prev with partial ciphertext, keep rest
            prev = cseg + prev[len(cseg):]

    return iv, b"".join(ciphertext_blocks)

def decrypt_cfb(block_encrypt: Callable[[bytes], bytes], block_size: int, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using CFB (Cipher Feedback) mode.
    
    CFB decryption is nearly identical to encryption:
    1. Start with the same IV used during encryption
    2. For each ciphertext segment:
       a. Encrypt the previous ciphertext block (or IV for first block)
       b. Use only the first len(segment) bytes of keystream
       c. XOR ciphertext segment with keystream to recover plaintext segment
       d. The ciphertext segment becomes the input to the next block cipher call
    
    Properties:
    - Uses only block_encrypt (same as CFB encryption)
    - CFB is symmetric: decrypt process is identical to encrypt process
    - IV must be the same as the one used during encryption
    - Works with any length data (no padding required)
    
    Args:
        block_encrypt: Callable that encrypts a block and returns keystream (same as encryption)
        block_size: Size of cipher blocks in bytes (must match encryption block_size)
        iv: Initialization Vector (bytes) - must be the same IV used during encryption
        ciphertext: Data to decrypt (bytes of any length)
    
    Returns:
        Decrypted plaintext (bytes) with same length as ciphertext
    
    Raises:
        ValueError: If IV length doesn't match block_size
    """
    # Validate IV length matches block size
    if len(iv) != block_size:
        raise ValueError("IV length must equal block size")

    plaintext_blocks = []
    prev = iv  # Previous ciphertext block (or IV for first iteration)
    
    # Process ciphertext in segments of up to block_size bytes
    for i in range(0, len(ciphertext), block_size):
        cseg = ciphertext[i:i+block_size]  # Current ciphertext segment
        
        # Generate the same keystream as during encryption
        keystream = block_encrypt(prev)
        
        # Truncate keystream to match segment length (for final partial block)
        ks_seg = keystream[:len(cseg)]
        
        # XOR ciphertext segment with keystream to recover plaintext segment
        pseg = bytes([c ^ k for c, k in zip(cseg, ks_seg)])
        plaintext_blocks.append(pseg)
        
        # Update prev for next iteration (same feedback mechanism as encryption)
        if len(cseg) == block_size:
            # Full block: use entire ciphertext block as next input
            prev = cseg
        else:
            # Partial block (final segment): shift register simulation
            prev = cseg + prev[len(cseg):]

    return b"".join(plaintext_blocks)

# -------------------------
# DummyBlockCipher (exemple)
# -------------------------
class DummyBlockCipher:
    """
    Dummy (non-cryptographic) block cipher for educational/testing purposes only.
    
    WARNING: This is NOT secure for real encryption. It's designed only to demonstrate
    how block cipher primitives work with CFB mode.
    
    Implementation: XOR each byte with 0xFF (bitwise NOT equivalent).
    Properties:
    - Deterministic: same input always produces same output
    - Reversible: XOR is its own inverse (f(f(x)) = x)
    - Weak: trivial to break, no cryptographic strength
    - Block padding: automatically pads partial blocks with zeros
    
    Attributes:
        block_size: Size of each block in bytes (default: 16, matching AES)
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
        Encrypt (or generate keystream for) a block by XORing with 0xFF.
        
        For CFB mode, this function acts as a keystream generator, so it just needs
        to produce deterministic output from input.
        
        Args:
            block: Input block (bytes). Automatically padded with zeros if smaller than block_size.
        
        Returns:
            Encrypted/keystream block (bytes of length block_size)
        
        Note: Padding with zeros is done implicitly for demonstration only.
              In real crypto, you would NOT pad here - CFB handles partial blocks.
        """
        if len(block) != self.block_size:
            # Pad with zeros if block is smaller (for example purposes only)
            block = block.ljust(self.block_size, b'\x00')
        
        # Simple XOR with 0xFF (non-secure, for demonstration)
        return bytes([b ^ 0xFF for b in block])

# -------------------------
# Exemple d'utilisation
# -------------------------
if __name__ == "__main__":
    # Initialize cipher with 16-byte blocks (matching AES block size)
    block_size = 16
    cipher = DummyBlockCipher(block_size=block_size)

    # Original plaintext - note: CFB works with ANY length, not just multiples of block_size
    plaintext = b"Texte en clair pour CFB mode - longueur non multiple du bloc!"
    print("Plaintext:", plaintext)
    print("Plaintext length:", len(plaintext), "bytes")

    # Encrypt using CFB mode
    # encrypt_cfb returns both the IV (for decryption) and the ciphertext
    iv, ct = encrypt_cfb(cipher.encrypt_block, block_size, plaintext)
    print("IV (hex):", iv.hex())
    print("Ciphertext (hex):", ct.hex())
    print("Ciphertext length:", len(ct), "bytes (same as plaintext)")

    # Decrypt using the same IV and ciphertext
    # The recovered plaintext should exactly match the original
    recovered = decrypt_cfb(cipher.encrypt_block, block_size, iv, ct)
    print("Recovered plaintext:", recovered)
    print("Match:", recovered == plaintext)  # Should be True
