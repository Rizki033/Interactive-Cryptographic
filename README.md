# 🔐 Interactive Cryptographic Suite with Execution-Time Profiling 

A comprehensive collection of **classical and modern cryptographic algorithms** implemented in Python for educational purposes. This repository demonstrates the principles, strengths, and weaknesses of various cryptographic techniques.

> ⚠️ **Disclaimer:** This code is for **educational purposes only**. Do NOT use in production environments. For real-world security, use well-tested libraries like `cryptography`, `PyCryptodome`, or `libsodium`.

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Directory Structure](#directory-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [Classical Ciphers](#classical-ciphers)
  - [Block Ciphers](#block-ciphers)
  - [Stream Ciphers](#stream-ciphers)
  - [Modern Ciphers](#modern-ciphers)
- [Features](#features)
- [Requirements](#requirements)
- [License](#license)

---

## 🎯 Project Overview

This repository implements various cryptographic algorithms across different categories:

- **Classical Ciphers**: Caesar, Vigenere, Hill Cipher
- **Block Cipher Modes**: ECB, CBC, CFB with DES and Triple DES
- **Stream Ciphers**: RC4, Vernam (One-Time Pad)
- **Symmetric Encryption**: AES with GUI demonstration

Each implementation includes:
- ✅ Full encryption/decryption functionality
- ✅ Detailed documentation and comments
- ✅ Example usage and demonstrations
- ✅ Performance measurement (where applicable)
- ✅ Educational analysis of security properties

---

## 📂 Directory Structure

```
Cryptography-scripting/
│
├── CaesarCipher/                 # Caesar Cipher (substitution)
│   ├── caesarCipher.py          # Core Caesar implementation
│   ├── caesarHacker.py          # Brute-force attack demo
│   └── README.md
│
├── Vigenere/                     # Vigenere Cipher (polyalphabetic)
│   ├── main.py                  # Core Vigenere implementation
│   └── README.md
│
├── Hill/                         # Hill Cipher (matrix-based)
│   ├── main.py                  # Core Hill implementation
│   ├── image.png                # Visual representation
│   └── README.md
│
├── Block-Cipher/                # Block Cipher Modes (DES, 3DES, AES)
│   ├── block_cipher_modes.py    # ECB, CBC, CFB implementations
│   ├── DES.py                   # DES with GUI (3 modes)
│   ├── TDES.py                  # Triple DES with GUI
│   ├── AES.py                   # AES cipher implementation
│   ├── images/                  # Supporting images
│   └── README.md
│
├── Stream-Cipher/               # Stream Ciphers
│   ├── RC4.py                   # RC4 algorithm
│   ├── image.png                # Visual representation
│   └── README.md
│
├── Vernam/                       # Vernam / One-Time Pad (OTP)
│   ├── main.py                  # Core OTP implementation
│   └── README.md
│
├── Module/                       # Utility modules
│   ├── example_aes.py
│   ├── modes.py
│   └── __pycache__/
│
├── Test/                         # Test scripts
│   ├── block_cipher_modes.py     # Unified cipher mode tests
│   └── DES.py                    # DES testing
│
├── .gitignore                    # Git ignore rules
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. **Clone the repository:**
```bash
git clone https://github.com/Rizki033/Cryptography-scripting.git
cd Cryptography-scripting
```

2. **Create a virtual environment:**
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

### Required Packages
```
pycryptodome>=3.18.0    # Cryptographic primitives
matplotlib>=3.5.0       # Graphing and visualization
psutil>=5.9.0          # System performance monitoring
cryptography>=40.0.0   # Modern cryptographic library
```

---

## 💻 Usage

### Classical Ciphers

#### Caesar Cipher
```bash
python CaesarCipher/caesarCipher.py
```
**Features:**
- Encrypt/decrypt with configurable shift
- Brute-force attack demonstration
- Performance statistics (CPU, memory usage)

#### Vigenere Cipher
```bash
python Vigenere/main.py
```
**Features:**
- Polyalphabetic substitution cipher
- Keyword-based encryption
- Perfect encryption/decryption reversal

#### Hill Cipher
```bash
python Hill/main.py
```
**Features:**
- Matrix-based encryption
- Linear algebra approach to cryptography

---

### Block Ciphers

#### DES with Graphical Interface
```bash
python Block-Cipher/DES.py
```
**Features:**
- 3 modes: ECB, CBC, CFB
- Real-time performance graphs
- Execution time and CPU monitoring
- IV (Initialization Vector) handling

#### Triple DES (3DES)
```bash
python Block-Cipher/TDES.py
```
**Features:**
- 2-key and 3-key variants
- ECB, CBC, CFB modes
- Performance statistics
- Proper EDE (Encrypt-Decrypt-Encrypt) implementation

#### AES Implementation
```bash
python Block-Cipher/AES.py
```
**Features:**
- Advanced Encryption Standard
- Multiple block cipher modes
- Efficient implementation

#### Block Cipher Modes Library
```python
from Block-Cipher.block_cipher_modes import encrypt_ecb, decrypt_ecb
from Block-Cipher.block_cipher_modes import encrypt_cbc, decrypt_cbc
from Block-Cipher.block_cipher_modes import encrypt_cfb, decrypt_cfb

# Example usage
plaintext = b"Secret message"
key = b"16_byte_key_123"
iv = b"16_byte_iv_12345"

# ECB mode (not recommended - no IV)
ciphertext = encrypt_ecb(block_encrypt_func, 16, plaintext)

# CBC mode (recommended)
ciphertext = encrypt_cbc(block_encrypt_func, 16, plaintext, iv)

# CFB mode (stream cipher mode)
ciphertext = encrypt_cfb(block_encrypt_func, 16, plaintext, iv)
```

---

### Stream Ciphers

#### Vernam / One-Time Pad (OTP)
```bash
python Vernam/main.py
```
**Features:**
- Perfect secrecy encryption
- Cryptographically secure random key generation
- Known-plaintext attack demonstration
- Key reuse vulnerability demo

#### RC4 Algorithm
```bash
python Stream-Cipher/RC4.py
```
**Features:**
- Stream cipher implementation
- Variable key length support
- Practical cipher example

---

## ✨ Features

### 🔒 Cipher Implementations
- **Classical**: Caesar, Vigenere, Hill
- **Block Modes**: ECB, CBC, CFB
- **Algorithms**: DES, 3DES, AES, RC4
- **Stream**: Vernam (OTP), RC4

### 📊 Analysis & Visualization
- Performance measurement (execution time, CPU usage, memory)
- Real-time graphing with matplotlib
- Statistical analysis of cipher operations
- Brute-force attack demonstrations

### 🎨 User Interfaces
- Tkinter-based GUI for interactive testing
- Command-line interfaces for scripting
- Real-time result visualization
- CSV export functionality

### 📚 Educational Content
- Comprehensive documentation
- ASCII art headers for visual appeal
- Detailed code comments
- Example usage demonstrations

---

## 🛠️ Key Algorithms

| Algorithm | Type | Key Size | Block Size | Security |
|-----------|------|----------|-----------|----------|
| Caesar | Classical | Variable | - | ❌ Weak |
| Vigenere | Classical | Variable | - | ❌ Weak |
| Hill | Classical | Variable | - | ❌ Weak |
| DES | Block | 56 bits | 64 bits | ⚠️ Deprecated |
| 3DES | Block | 168 bits | 64 bits | ⚠️ Legacy |
| AES | Block | 128/192/256 | 128 bits | ✅ Strong |
| RC4 | Stream | Variable | - | ⚠️ Flawed |
| Vernam | Stream | =Plaintext | - | ✅ Perfect |

---

## 🔍 Security Considerations

### Good Practices Demonstrated
- PKCS#7 padding for block ciphers
- Random IV generation
- Proper mode usage (CBC, CFB > ECB)
- Cryptographically secure RNG

### Vulnerabilities Explored
- ECB mode pattern leakage
- Key reuse in stream ciphers
- Known-plaintext attacks
- Brute-force susceptibility

### What NOT to Do
- **Don't use classical ciphers** for real data
- **Don't reuse keys** in stream ciphers
- **Don't use ECB mode** for sensitive data
- **Don't implement crypto yourself** for production

---

## 📖 Example Code

### Simple Caesar Cipher
```python
from CaesarCipher.caesarCipher import caesar_encrypt, caesar_decrypt

plaintext = "HELLO WORLD"
key = 3

ciphertext = caesar_encrypt(plaintext, key)
print(f"Encrypted: {ciphertext}")

decrypted = caesar_decrypt(ciphertext, key)
print(f"Decrypted: {decrypted}")
```

### Vigenere Cipher
```python
from Vigenere.main import encrypt_vigenere, decrypt_vigenere

plaintext = "TO BE OR NOT TO BE"
keyword = "RELATIONS"

ciphertext = encrypt_vigenere(plaintext, keyword)
print(f"Ciphertext: {ciphertext}")

plaintext_recovered = decrypt_vigenere(ciphertext, keyword)
print(f"Recovered: {plaintext_recovered}")
```

### Vernam (One-Time Pad)
```python
from Vernam.main import generate_key, encrypt, decrypt

message = "HELLO OTP"
pt_bytes = message.encode('utf-8')

key = generate_key(len(pt_bytes))  # Key length = plaintext length
ciphertext = encrypt(pt_bytes, key)
plaintext = decrypt(ciphertext, key)

print(f"Original: {message}")
print(f"Recovered: {plaintext.decode('utf-8')}")
```

---

## 🧪 Testing

Run test files:
```bash
python Test/block_cipher_modes.py
python Block-Cipher/DES.py  # GUI test
python Block-Cipher/TDES.py # GUI test
```

All implementations include:
- Input validation
- Error handling
- Example demonstrations
- Docstring documentation

---

## Performance Metrics

The GUI applications measure:
- **Execution Time**: Wall-clock time in milliseconds
- **CPU Usage**: Process CPU percentage
- **Memory Usage**: RSS (Resident Set Size)
- **Python Memory**: Allocated memory by Python objects

Results can be exported to CSV for analysis.

---


## 🎓 Learning Path

Suggested order for learning:

1. **Start here**: Caesar Cipher → Vigenere → Hill
2. **Block Ciphers**: DES → Triple DES → AES
3. **Modes**: ECB → CBC → CFB
4. **Stream Ciphers**: RC4 → Vernam (OTP)
5. **Analysis**: Attack demonstrations → Performance metrics

---

## References

- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)
- [NIST Cryptographic Algorithms](https://csrc.nist.gov/)
- [Cryptography Basics](https://en.wikipedia.org/wiki/Cryptography)
- [Block Cipher Modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

---
## Quick Start

```bash
# Clone repository
git clone https://github.com/Rizki033/Cryptography-scripting.git
cd Cryptography-scripting

# Setup environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run examples
python Vigenere/main.py          # Classical cipher
python Block-Cipher/DES.py       # Block cipher GUI
python Vernam/main.py            # Stream cipher

# Explore each subdirectory for more examples!
```

---

**Happy Learning! 🎓 Remember: Security through Education!**
