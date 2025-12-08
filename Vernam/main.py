#!/usr/bin/env python3
from secrets import token_bytes
from typing import Tuple
import os

# -------------------------
# Core functions
# -------------------------
def generate_key(length: int) -> bytes:
    """
    Generate a cryptographically-random key of `length` bytes.
    For OTP the key length MUST equal the plaintext length (in bytes).
    """
    if length <= 0:
        raise ValueError("length must be > 0")
    return token_bytes(length)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte sequences of equal length and return the result.
    """
    if len(a) != len(b):
        raise ValueError("xor_bytes requires inputs of equal length")
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(plaintext_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    OTP encryption (bitwise XOR). plaintext_bytes and key_bytes must have same length.
    Returns ciphertext bytes.
    """
    return xor_bytes(plaintext_bytes, key_bytes)

def decrypt(ciphertext_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    OTP decryption is identical to encryption (XOR with same key).
    """
    return xor_bytes(ciphertext_bytes, key_bytes)

# -------------------------
# Helpers for text and files
# -------------------------
def encrypt_text(plaintext: str, key: bytes, encoding='utf-8') -> bytes:
    p = plaintext.encode(encoding)
    if len(p) != len(key):
        raise ValueError("Key length must equal plaintext length in bytes.")
    return encrypt(p, key)

def decrypt_text(ciphertext: bytes, key: bytes, encoding='utf-8') -> str:
    p = decrypt(ciphertext, key)
    return p.decode(encoding)

def encrypt_file(in_path: str, out_path: str, key: bytes) -> None:
    """
    Encrypt a binary file with OTP. key length must equal file size.
    """
    with open(in_path, 'rb') as f:
        data = f.read()
    if len(data) != len(key):
        raise ValueError("Key length must equal file size.")
    ct = encrypt(data, key)
    with open(out_path, 'wb') as f:
        f.write(ct)

def decrypt_file(in_path: str, out_path: str, key: bytes) -> None:
    with open(in_path, 'rb') as f:
        data = f.read()
    if len(data) != len(key):
        raise ValueError("Key length must equal file size.")
    pt = decrypt(data, key)
    with open(out_path, 'wb') as f:
        f.write(pt)

# -------------------------
# Known-plaintext attack demo
# -------------------------
def recover_key_from_known_plaintext(known_plaintext: bytes, ciphertext: bytes) -> bytes:
    """
    If attacker knows plaintext and has ciphertext, they can recover the key:
    key = plaintext XOR ciphertext
    """
    if len(known_plaintext) != len(ciphertext):
        raise ValueError("Lengths must match")
    return xor_bytes(known_plaintext, ciphertext)

# -------------------------
# Utility to show bits/hex
# -------------------------
def to_hex(b: bytes) -> str:
    return b.hex()

def to_bin_string(b: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in b)

# --------
# Example 
# --------
def example():
    print("=== Vernam / One-Time-Pad example ===\n")

    message = "HELLO OTP"  # example plaintext
    encoding = 'utf-8'
    pt_bytes = message.encode(encoding)
    print("Plaintext:", message)
    print("Plaintext (hex):", to_hex(pt_bytes))
    print("Plaintext (bin):", to_bin_string(pt_bytes))

    # Generate key of exact same byte length
    key = generate_key(len(pt_bytes))
    print("\nGenerated key (hex):", to_hex(key))
    print("Generated key (bin):", to_bin_string(key))

    # Encrypt
    ct = encrypt(pt_bytes, key)
    print("\nCiphertext (hex):", to_hex(ct))
    print("Ciphertext (bin):", to_bin_string(ct))
    try:
        print("Ciphertext (utf-8 attempt):", ct.decode('utf-8'))
    except:
        print("Ciphertext not valid UTF-8 (expected)")

    # Decrypt
    recovered = decrypt(ct, key)
    print("\nDecrypted (hex):", to_hex(recovered))
    print("Decrypted text:", recovered.decode(encoding))

    # Known-plaintext attack demonstration:
    # Suppose attacker knows `recovered` or any known plaintext-substring,
    # they can recover the key bits for that area:
    print("\n--- Known-plaintext attack demo ---")
    known = pt_bytes  # attacker knows full plaintext in this demo
    recovered_key = recover_key_from_known_plaintext(known, ct)
    print("Recovered key equals original key?", recovered_key == key)

    # Show the catastrophic effect of key reuse:
    print("\n--- Key reuse demonstration (never reuse key!) ---")
    # Encrypt second message with same key (WRONG)
    message2 = "ATTACK NOW"
    pt2 = message2.encode(encoding)
    if len(pt2) != len(key):
        # pad/truncate for the demo to same length (just for demonstration)
        pt2 = pt2[:len(key)].ljust(len(key), b'X')
    ct2 = encrypt(pt2, key)
    # An attacker who knows first plaintext and both ciphertexts can obtain pt2:
    # Using recovered_key (from known pt1) attacker computes pt2 = ct2 XOR recovered_key
    leaked_pt2 = xor_bytes(ct2, recovered_key)
    print("Original second plaintext (maybe with padding):", pt2)
    print("Recovered second plaintext by attacker (if key reused):", leaked_pt2)
    print("If key reused, security is broken! Do NOT reuse keys.\n")

# -------------------------
# Run example if module executed
# -------------------------
if __name__ == "__main__":
    example()
