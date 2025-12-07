from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class BlockCipherModes:
    """
    Module générique pour chiffrer/déchiffrer avec AES, DES ou 3DES
    dans les modes : ECB, CBC et CFB.
    """

    def __init__(self, key, algorithm="AES"):
        self.algorithm = algorithm.upper()

        if self.algorithm == "AES":
            self.block_size = 16
            self.cipher_algo = AES
        elif self.algorithm == "DES":
            self.block_size = 8
            self.cipher_algo = DES
        elif self.algorithm == "3DES":
            self.block_size = 8
            self.cipher_algo = DES3
        else:
            raise ValueError("Algorithme non supporté !")

        self.key = key

    def encrypt(self, plaintext, mode="ECB"):
        plaintext = plaintext.encode()

        mode = mode.upper()
        if mode == "ECB":
            cipher = self.cipher_algo.new(self.key, self.cipher_algo.MODE_ECB)
            ciphertext = cipher.encrypt(pad(plaintext, self.block_size))
            return ciphertext, None  # Pas d'IV en ECB

        elif mode == "CBC":
            iv = get_random_bytes(self.block_size)
            cipher = self.cipher_algo.new(self.key, self.cipher_algo.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext, self.block_size))
            return ciphertext, iv

        elif mode == "CFB":
            iv = get_random_bytes(self.block_size)
            cipher = self.cipher_algo.new(self.key, self.cipher_algo.MODE_CFB, iv)
            ciphertext = cipher.encrypt(plaintext)
            return ciphertext, iv

        else:
            raise ValueError("Mode de chiffrement non supporté")

    def decrypt(self, ciphertext, mode="ECB", iv=None):

        mode = mode.upper()
        if mode == "ECB":
            cipher = self.cipher_algo.new(self.key, self.cipher_algo.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), self.block_size)
            return plaintext.decode()

        elif mode == "CBC":
            cipher = self.cipher_algo.new(self.key, self.cipher_algo.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), self.block_size)
            return plaintext.decode()

        elif mode == "CFB":
            cipher = self.cipher_algo.new(self.key, self.cipher_algo.MODE_CFB, iv)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode()

        else:
            raise ValueError("Mode de chiffrement non supporté")
