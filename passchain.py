import argparse
import os
import sys
 
import psycopg2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# Encryption Data
# --------------------------------------------------------------------------
SCRYPT_N = 2**17   # scrypt iterations
SCRYPT_R = 8       # scrypt block size
SCRYPT_P = 1       # scrypt parallelization
KEY_LEN  = 32      # 256-bit key for AES-256-GCM

def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return nonce, ct
 
 
def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """Decrypt AES-256-GCM. Raises InvalidTag on wrong key or tampered data."""
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()
