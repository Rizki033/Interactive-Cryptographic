#!/usr/bin/env python3
"""
Vigenere Cipher (Classic Implementation)
- Works on A–Z only
- Removes spaces and converts to uppercase
- Repeats keyword automatically
- Includes encrypt() and decrypt()
"""

def clean_text(txt: str) -> str:
    """
    Keep only alphabetic letters, convert to uppercase.
    """
    return "".join(ch for ch in txt.upper() if ch.isalpha())


def repeat_keyword(keyword: str, length: int) -> str:
    """
    Repeat the keyword until it matches the desired length.
    """
    keyword = clean_text(keyword)
    if len(keyword) == 0:
        raise ValueError("Keyword must contain letters.")
    return (keyword * ((length // len(keyword)) + 1))[:length]


def encrypt_vigenere(plaintext: str, keyword: str) -> str:
    """
    Encrypt plaintext using Vigenere cipher.
    Formula: C = (P + K) mod 26
    """
    pt = clean_text(plaintext)
    key = repeat_keyword(keyword, len(pt))

    ciphertext = []
    for p, k in zip(pt, key):
        c = (ord(p) - ord('A') + (ord(k) - ord('A'))) % 26
        ciphertext.append(chr(c + ord('A')))
    return "".join(ciphertext)


def decrypt_vigenere(ciphertext: str, keyword: str) -> str:
    """
    Decrypt Vigenere cipher.
    Formula: P = (C - K + 26) mod 26
    """
    ct = clean_text(ciphertext)
    key = repeat_keyword(keyword, len(ct))

    plaintext = []
    for c, k in zip(ct, key):
        p = (ord(c) - ord('A') - (ord(k) - ord('A'))) % 26
        plaintext.append(chr(p + ord('A')))
    return "".join(plaintext)


# -----------------------
# Example from your text
# -----------------------
def example():
    keyword = "RELATIONS"
    plaintext = "TO BE OR NOT TO BE THAT IS THE QUESTION"

    print("Plaintext :", plaintext)
    print("Keyword   :", keyword)

    ciphertext = encrypt_vigenere(plaintext, keyword)
    print("\nCiphertext:", ciphertext)

    decrypted = decrypt_vigenere(ciphertext, keyword)
    print("Decrypted :", decrypted)


if __name__ == "__main__":
    example()
