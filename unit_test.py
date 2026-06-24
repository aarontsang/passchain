#!/usr/bin/env python3
"""
Unit tests for passchain.py

Requires PASSCHAIN_DSN to be set:
  export PASSCHAIN_DSN='postgresql://aarontsang@localhost/passchain'

Run with:
  python3 test_passchain.py
"""

import os
import sys
import unittest

import psycopg2

# Import from passchain (must be in the same directory or on the path)
from passchain import (
    derive_key,
    encrypt,
    decrypt,
    ensure_tables,
    set_master_key,
    master_set,
    verify_master_key,
    get_conn,
    get_dsn,
)

# --------------------------------------------------------------------------
# Dummy test data
# --------------------------------------------------------------------------
MASTER_PASSWORD = "TestMaster123"
SERVICE         = "github"
USERNAME        = "testuser"
PASSWORD        = "supersecret42"


class TestEncryption(unittest.TestCase):
    """Tests that don't touch the database."""

    def test_derive_key_length(self):
        salt = os.urandom(16)
        key = derive_key(MASTER_PASSWORD, salt)
        self.assertEqual(len(key), 32)

    def test_derive_key_deterministic(self):
        salt = os.urandom(16)
        key1 = derive_key(MASTER_PASSWORD, salt)
        key2 = derive_key(MASTER_PASSWORD, salt)
        self.assertEqual(key1, key2)

    def test_derive_key_different_salts(self):
        key1 = derive_key(MASTER_PASSWORD, os.urandom(16))
        key2 = derive_key(MASTER_PASSWORD, os.urandom(16))
        self.assertNotEqual(key1, key2)

    def test_encrypt_decrypt_roundtrip(self):
        salt = os.urandom(16)
        key = derive_key(MASTER_PASSWORD, salt)
        nonce, ciphertext = encrypt(PASSWORD, key)
        result = decrypt(nonce, ciphertext, key)
        self.assertEqual(result, PASSWORD)

    def test_decrypt_wrong_key_raises(self):
        salt = os.urandom(16)
        key = derive_key(MASTER_PASSWORD, salt)
        nonce, ciphertext = encrypt(PASSWORD, key)

        wrong_key = derive_key("wrongpassword", os.urandom(16))
        with self.assertRaises(Exception):
            decrypt(nonce, ciphertext, wrong_key)

    def test_encrypt_nonce_unique(self):
        salt = os.urandom(16)
        key = derive_key(MASTER_PASSWORD, salt)
        nonce1, _ = encrypt(PASSWORD, key)
        nonce2, _ = encrypt(PASSWORD, key)
        self.assertNotEqual(nonce1, nonce2)


class TestDatabase(unittest.TestCase):
    """Tests that require a live PostgreSQL connection."""

    @classmethod
    def setUpClass(cls):
        cls.conn = get_conn(get_dsn())
        ensure_tables(cls.conn)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def setUp(self):
        # Each test runs inside a transaction that gets rolled back in tearDown
        self.conn.autocommit = False

    def tearDown(self):
        self.conn.rollback()

    # ------------------------------------------------------------------
    # Master password
    # ------------------------------------------------------------------

    def test_master_not_set_initially(self):
        self.assertFalse(master_set(self.conn))

    def test_set_and_detect_master(self):
        set_master_key(self.conn, MASTER_PASSWORD, commit=False)
        self.assertTrue(master_set(self.conn))

    def test_verify_master_correct(self):
        set_master_key(self.conn, MASTER_PASSWORD, commit=False)
        self.assertTrue(verify_master_key(self.conn, MASTER_PASSWORD))

    def test_verify_master_wrong_password(self):
        set_master_key(self.conn, MASTER_PASSWORD, commit=False)
        self.assertFalse(verify_master_key(self.conn, "wrongpassword"))

    # ------------------------------------------------------------------
    # Entries
    # ------------------------------------------------------------------

    def _insert_entry(self, service=SERVICE, username=USERNAME, password=PASSWORD):
        """Helper: directly insert an encrypted entry."""
        salt = os.urandom(16)
        key = derive_key(MASTER_PASSWORD, salt)
        nonce, ciphertext = encrypt(password, key)
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO passchain_entries (service, username, kdf_salt, nonce, ciphertext)
                VALUES (%s, %s, %s, %s, %s)
            """, (service, username, salt, nonce, ciphertext))

        return salt

    def test_insert_and_retrieve_entry(self):
        self._insert_entry()
        with self.conn.cursor() as cur:
            cur.execute("SELECT kdf_salt, nonce, ciphertext FROM passchain_entries WHERE service = %s AND username = %s",
                        (SERVICE, USERNAME))
            row = cur.fetchone()
        self.assertIsNotNone(row)
        kdf_salt, nonce, ciphertext = row
        key = derive_key(MASTER_PASSWORD, bytes(kdf_salt))
        result = decrypt(bytes(nonce), bytes(ciphertext), key)
        self.assertEqual(result, PASSWORD)

    def test_entry_not_found(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT * FROM passchain_entries WHERE service = %s AND username = %s",
                        ("nonexistent", "nobody"))
            row = cur.fetchone()
        self.assertIsNone(row)

    def test_update_entry(self):
        self._insert_entry()
        new_password = "updatedpassword99"
        salt = os.urandom(16)
        key = derive_key(MASTER_PASSWORD, salt)
        nonce, ciphertext = encrypt(new_password, key)
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE passchain_entries
                SET kdf_salt = %s, nonce = %s, ciphertext = %s
                WHERE service = %s AND username = %s
            """, (salt, nonce, ciphertext, SERVICE, USERNAME))


        with self.conn.cursor() as cur:
            cur.execute("SELECT kdf_salt, nonce, ciphertext FROM passchain_entries WHERE service = %s AND username = %s",
                        (SERVICE, USERNAME))
            row = cur.fetchone()
        key = derive_key(MASTER_PASSWORD, bytes(row[0]))
        result = decrypt(bytes(row[1]), bytes(row[2]), key)
        self.assertEqual(result, new_password)

    def test_delete_entry(self):
        self._insert_entry()
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM passchain_entries WHERE service = %s AND username = %s",
                        (SERVICE, USERNAME))

        with self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM passchain_entries WHERE service = %s AND username = %s",
                        (SERVICE, USERNAME))
            count = cur.fetchone()[0]
        self.assertEqual(count, 0)

    def test_duplicate_entry_rejected(self):
        self._insert_entry()
        with self.assertRaises(psycopg2.errors.UniqueViolation):
            self._insert_entry()
        self.conn.rollback()

    def test_list_entries(self):
        self._insert_entry(service="github",   username="alice")
        self._insert_entry(service="twitter",  username="alice")
        self._insert_entry(service="linkedin", username="alice")
        with self.conn.cursor() as cur:
            cur.execute("SELECT service, username FROM passchain_entries ORDER BY service")
            rows = cur.fetchall()
        services = [r[0] for r in rows]
        self.assertEqual(sorted(services), ["github", "linkedin", "twitter"])


if __name__ == "__main__":
    unittest.main(verbosity=2)