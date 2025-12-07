from modes import BlockCipherModes
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)  # AES-128
cipher = BlockCipherModes(key, "AES")

ciphertext, iv = cipher.encrypt("Bonjour Ifrane!", mode="CBC")
print("Chiffré :", ciphertext.hex())

plaintext = cipher.decrypt(ciphertext, mode="CBC", iv=iv)
print("Déchiffré :", plaintext)
