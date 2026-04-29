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

# --------------------------------------------------------------------------
# Database Access
# --------------------------------------------------------------------------

def get_dsn() -> str:
    dsn = os.environ.get("PASSCHAIN_DSN")
    if not dsn:
        sys.exit(
            "[passchain] Set the PASSCHAIN_DSN environment variable.\n"
            "  Example: export PASSCHAIN_DSN='postgresql://user:pass@localhost/passchain'"
        )
    return dsn

def get_conn(dsn: str):
    try:
        return psycopg2.connect(dsn)
    except psycopg2.OperationalError as e:
        sys.exit(f"[passchain] Cannot connect to database: {e}")

def ensure_tables(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passchain_master (
                id         SERIAL PRIMARY KEY,
                kdf_salt   BYTEA NOT NULL,
                nonce      BYTEA NOT NULL,
                verifier   BYTEA NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passchain_entries (
                service    TEXT   NOT NULL,
                username   TEXT   NOT NULL,
                kdf_salt   BYTEA  NOT NULL,
                nonce      BYTEA  NOT NULL,
                ciphertext BYTEA  NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE (service, username)
            )
        """)
    conn.commit()