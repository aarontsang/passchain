import argparse
import os
import sys
import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import psycopg2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# Encryption Data
# --------------------------------------------------------------------------
SCRYPT_N = 2**17   # scrypt iterations
SCRYPT_R = 8       # scrypt block size
SCRYPT_P = 1       # scrypt parallelization
KEY_LEN  = 32      # 256-bit key for AES-256-GCM

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the master password using scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(master_password.encode())

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

# --------------------------------------------------------------------------
# Master Key Management
# --------------------------------------------------------------------------

VERIFIER_PLAINTEXT = "passchain-ok"

def set_master_key(conn, master_key: bytes):
    """Initialize master key. Should be called once."""
    kdf_salt = os.urandom(16)
    nonce, verifier = encrypt(VERIFIER_PLAINTEXT, master_key)
    with conn.cursor() as cur:
        cur.execute("INSERT INTO passchain_master (kdf_salt, nonce, verifier) VALUES (%s, %s, %s)",
                    (kdf_salt, nonce, verifier))
    conn.commit()

def master_set(conn) -> bool:
    """Check if master key is set up. Returns True if already initialized."""
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM passchain_master")
        return cur.fetchone()[0] > 0

def verify_master_key(conn, master_key: bytes) -> bool:
    """Verify master key by decrypting the verifier."""
    with conn.cursor() as cur:
        cur.execute("SELECT kdf_salt, nonce, verifier FROM passchain_master LIMIT 1")
        row = cur.fetchone()
        if not row:
            return False
        kdf_salt, nonce, verifier = row
        try:
            decrypted = decrypt(nonce, verifier, master_key)
            return decrypted == VERIFIER_PLAINTEXT
        except Exception:
            return False
        
# --------------------------------------------------------------------------
# CLI Commands
# --------------------------------------------------------------------------

def cmd_init(conn):
    if master_set(conn):
        print("[passchain] Master password already set.")
        print("           To change it, run: passchain change-master")
        return
 
    pw1 = getpass.getpass("Set master password: ")
    pw2 = getpass.getpass("Confirm master password: ")
    if pw1 != pw2:
        sys.exit("[passchain] Passwords do not match.")
    if len(pw1) < 8:
        sys.exit("[passchain] Master password must be at least 8 characters.")
 
    set_master_key(conn, pw1)

def cmd_add(conn, args):
    service = args.service.strip().lower()
    username = args.username.strip()

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM passchain_entries WHERE service = %s AND username = %s",
                    (service, username))
        exists = cur.fetchone() is not None

    if exists:
        print(f"[passchain] Entry for {service} / {username} already exists.")
        print("           To update it, run: passchain update")
        return

    for i in range(5):
        master_pw = getpass.getpass("Master password: ")
        if verify_master_key(conn, master_pw):
            break
        print("[passchain] Incorrect master password. {} attempts left. Try again.".format(4 - i))
    else:
        sys.exit("[passchain] Incorrect master password.")
    
    # TODO: Extract to a password verifier to make sure it meets certain requirements
    password = getpass.getpass(f"Password for {service} / {username}: ")
    if not password:
        sys.exit("[passchain] Password cannot be empty.")

    salt = os.urandom(16)
    key = derive_key(master_pw.encode(), salt)
    nonce, ciphertext = encrypt(password, key)

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO passchain_entries (service, username, kdf_salt, nonce, ciphertext)
            VALUES (%s, %s, %s, %s, %s)
        """, (service, username, salt, nonce, ciphertext))
    conn.commit()

    print(f"[passchain] Entry for {service} / {username} added successfully.")
            
def main():
    conn = get_conn(get_dsn())
    ensure_tables(conn)

    # Placeholder for CLI commands (e.g., init, add, get, list)
    print("[passchain] Database initialized and ready.")
    conn.close()
 
 
if __name__ == "__main__":
    main()