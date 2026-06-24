#!/usr/bin/env python3

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
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN  = 32

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the master password using scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return bytes(kdf.derive(master_password.encode()))

def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)  # key is already bytes
    return nonce, ct

def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """Decrypt AES-256-GCM. Raises InvalidTag on wrong key or tampered data."""
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()  # key is already bytes

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

def set_master_key(conn, master_password: str, commit: bool = True):
    """Initialize master key. Should be called once."""
    salt = os.urandom(16)
    key = derive_key(master_password, salt)  # derive key from password
    nonce, verifier = encrypt(VERIFIER_PLAINTEXT, key)
    with conn.cursor() as cur:
        cur.execute("INSERT INTO passchain_master (kdf_salt, nonce, verifier) VALUES (%s, %s, %s)",
                    (salt, nonce, verifier))
    if commit:
        conn.commit()

def master_set(conn) -> bool:
    """Check if master key is set up. Returns True if already initialized."""
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM passchain_master")
        return cur.fetchone()[0] > 0

def verify_master_key(conn, master_password: str) -> bool:
    """Verify master password by decrypting the verifier."""
    with conn.cursor() as cur:
        cur.execute("SELECT kdf_salt, nonce, verifier FROM passchain_master LIMIT 1")
        row = cur.fetchone()
        if not row:
            return False
        kdf_salt, nonce, verifier = row
        try:
            key = derive_key(master_password, bytes(kdf_salt))
            decrypted = decrypt(bytes(nonce), bytes(verifier), key)
            return decrypted == VERIFIER_PLAINTEXT
        except Exception:
            return False

# --------------------------------------------------------------------------
# CLI Commands
# --------------------------------------------------------------------------

def prompt_master(conn) -> str:
    """Prompt for master password with up to 5 attempts."""
    for i in range(5):
        master_pw = getpass.getpass("Master password: ")
        if verify_master_key(conn, master_pw):
            return master_pw
        print("[passchain] Incorrect master password. {} attempts left.".format(4 - i))
    sys.exit("[passchain] Too many incorrect attempts.")

def cmd_init(conn, args):
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

    set_master_key(conn, pw1)  # pass raw password, derive_key happens inside
    print("[passchain] Master password set successfully.")

def cmd_add(conn, args):
    service = args.service.strip().lower()
    username = args.username.strip()

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM passchain_entries WHERE service = %s AND username = %s",
                    (service, username))
        exists = cur.fetchone()[0] > 0  # fixed: was checking fetchone() is not None (always True)

    if exists:
        print(f"[passchain] Entry for {service} / {username} already exists.")
        print("           To update it, run: passchain update")
        return

    master_pw = prompt_master(conn)

    password = getpass.getpass(f"Password for {service} / {username}: ")
    if not password:
        sys.exit("[passchain] Password cannot be empty.")

    salt = os.urandom(16)
    key = derive_key(master_pw, salt)
    nonce, ciphertext = encrypt(password, key)

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO passchain_entries (service, username, kdf_salt, nonce, ciphertext)
            VALUES (%s, %s, %s, %s, %s)
        """, (service, username, salt, nonce, ciphertext))
    conn.commit()

    print(f"[passchain] Entry for {service} / {username} added successfully.")

def cmd_update(conn, args):
    service = args.service.strip().lower()
    username = args.username.strip()

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM passchain_entries WHERE service = %s AND username = %s",
                    (service, username))
        exists = cur.fetchone()[0] > 0  # fixed: was checking fetchone() is not None (always True)

    if not exists:
        print(f"[passchain] Entry for {service} / {username} does not exist.")
        print("           To add it, run: passchain add")
        return

    master_pw = prompt_master(conn)

    password = getpass.getpass(f"New password for {service} / {username}: ")
    if not password:
        sys.exit("[passchain] Password cannot be empty.")

    salt = os.urandom(16)
    key = derive_key(master_pw, salt)
    nonce, ciphertext = encrypt(password, key)

    with conn.cursor() as cur:
        cur.execute("""
            UPDATE passchain_entries
            SET kdf_salt = %s, nonce = %s, ciphertext = %s
            WHERE service = %s AND username = %s
        """, (salt, nonce, ciphertext, service, username))  # fixed: salt/nonce/ct must come before service/username
    conn.commit()

    print(f"[passchain] Entry for {service} / {username} updated successfully.")

def cmd_get(conn, args):
    service = args.service.strip().lower()
    username = args.username.strip()

    master_pw = prompt_master(conn)

    with conn.cursor() as cur:
        cur.execute("SELECT kdf_salt, nonce, ciphertext FROM passchain_entries WHERE service = %s AND username = %s",
                    (service, username))
        row = cur.fetchone()
        if not row:
            sys.exit(f"[passchain] Entry for {service} / {username} not found.")
        kdf_salt, nonce, ciphertext = row

    key = derive_key(master_pw, bytes(kdf_salt))
    try:
        password = decrypt(bytes(nonce), bytes(ciphertext), key)
        print(f"[passchain] Password for {service} / {username}: {password}")
    except Exception:
        sys.exit("[passchain] Failed to decrypt password. Possible data corruption or wrong master key.")

def cmd_list(conn, args):
    prompt_master(conn)

    with conn.cursor() as cur:
        cur.execute("SELECT service, username FROM passchain_entries ORDER BY service DESC")
        rows = cur.fetchall()
        if not rows:
            print("[passchain] No entries found.")
            return
        print("[passchain] Stored entries:")
        for service, username in rows:
            print(f"  - {service} / {username}")

def cmd_delete(conn, args):
    service = args.service.strip().lower()
    username = args.username.strip()

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM passchain_entries WHERE service = %s AND username = %s",
                    (service, username))
        exists = cur.fetchone()[0] > 0

    if not exists:
        print(f"[passchain] Entry for {service} / {username} does not exist.")
        return

    prompt_master(conn)

    with conn.cursor() as cur:
        cur.execute("DELETE FROM passchain_entries WHERE service = %s AND username = %s",
                    (service, username))
    conn.commit()

    print(f"[passchain] Entry for {service} / {username} deleted successfully.")

def cmd_change_master(conn, args):
    if not master_set(conn):
        print("[passchain] Master password is not set. Run 'passchain init' first.")
        return

    old_master_pw = prompt_master(conn)

    new_pw1 = getpass.getpass("New master password: ")
    new_pw2 = getpass.getpass("Confirm new master password: ")
    if new_pw1 != new_pw2:
        sys.exit("[passchain] New passwords do not match.")
    if len(new_pw1) < 8:
        sys.exit("[passchain] New master password must be at least 8 characters.")

    with conn.cursor() as cur:
        cur.execute("SELECT service, username, kdf_salt, nonce, ciphertext FROM passchain_entries")
        entries = cur.fetchall()

    new_salt = os.urandom(16)
    new_master_key = derive_key(new_pw1, new_salt)

    for service, username, kdf_salt, nonce, ciphertext in entries:
        old_key = derive_key(old_master_pw, bytes(kdf_salt))
        try:
            plaintext = decrypt(bytes(nonce), bytes(ciphertext), old_key)
        except Exception:
            sys.exit(f"[passchain] Failed to decrypt entry for {service} / {username}. Aborting.")

        new_nonce, new_ciphertext = encrypt(plaintext, new_master_key)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE passchain_entries
                SET kdf_salt = %s, nonce = %s, ciphertext = %s
                WHERE service = %s AND username = %s
            """, (new_salt, new_nonce, new_ciphertext, service, username))

    with conn.cursor() as cur:
        cur.execute("DELETE FROM passchain_master")

    set_master_key(conn, new_pw1, commit=False)  # now accepts commit param
    conn.commit()
    print(f"[passchain] Done. {len(entries)} entries re-encrypted.")

def main():
    conn = get_conn(get_dsn())
    ensure_tables(conn)

    parser = argparse.ArgumentParser(
        prog="passchain",
        description="Local encrypted password manager with blockchain integrity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init",          help="First-time setup")
    sub.add_parser("change-master", help="Change master password (re-encrypts all entries)")

    p_add = sub.add_parser("add",    help="Add a credential")
    p_add.add_argument("service")
    p_add.add_argument("username")

    p_update = sub.add_parser("update", help="Update a credential")
    p_update.add_argument("service")
    p_update.add_argument("username")

    p_get = sub.add_parser("get",    help="Retrieve a credential")
    p_get.add_argument("service")
    p_get.add_argument("username")

    p_list = sub.add_parser("list",  help="List all credentials (no passwords shown)")
    p_list.add_argument("service", nargs="?", default=None, help="Optional service filter")

    p_del = sub.add_parser("delete", help="Delete a credential")
    p_del.add_argument("service")
    p_del.add_argument("username")

    args = parser.parse_args()

    dispatch = {
        "init":          cmd_init,
        "add":           cmd_add,
        "update":        cmd_update,
        "get":           cmd_get,
        "list":          cmd_list,
        "delete":        cmd_delete,
        "change-master": cmd_change_master,
    }
    dispatch[args.command](conn, args)
    conn.close()


if __name__ == "__main__":
    main()