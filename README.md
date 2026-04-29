# passchain

A local, encrypted password manager backed by PostgreSQL.

Passwords are encrypted with **AES-256-GCM**. Your master password is never
stored — it's used to derive encryption keys via **scrypt** (N=2¹⁷), so
brute-forcing offline is expensive. Each credential gets its own random
salt, so a compromised entry leaks nothing about the others.

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Create a PostgreSQL database

```bash
# Create a dedicated DB (do this once)
createdb passchain

# Or with a full connection string:
psql -c "CREATE DATABASE passchain;"
```

### 3. Set the connection string

Add this to your shell profile (`~/.zshrc`, `~/.bashrc`, etc.):

```bash
export PASSCHAIN_DSN="postgresql://YOUR_USER@localhost/passchain"
# If you have a password:
# export PASSCHAIN_DSN="postgresql://YOUR_USER:YOUR_PASS@localhost/passchain"
```

Then reload: `source ~/.zshrc`

### 4. (Optional) Make passchain available globally

```bash
chmod +x passchain.py
sudo ln -s "$(pwd)/passchain.py" /usr/local/bin/passchain
```

Or add the project folder to your PATH.

### 5. Initialize

```bash
passchain init
```

This creates the DB tables and sets your master password.

---

## Usage

```bash
# Add a credential (prompts for master password + the password to store)
passchain add gmail personal@gmail.com
passchain add gmail work@company.com

# Change a credential (prompts for master password + the old password + the new password)
passchain update gmail personal@gmail.com

# Retrieve a credential
passchain get gmail personal@gmail.com

# List all entries (no passwords shown)
passchain list

# List entries for a specific service
passchain list github

# Delete an entry
passchain delete gmail old@gmail.com

# Change master password (re-encrypts every entry)
passchain change-master
```

---

## Security design

| Concern | Solution |
|---|---|
| Passwords security | AES-256-GCM encryption, never stored in plaintext |
| Master password storage | Never stored — used only to derive keys via scrypt |
| Wrong master password detection | Encrypted verifier checked before any DB read |
| Per-entry key isolation | Each entry has its own random 32-byte salt |
| Key derivation cost | scrypt N=2¹⁷ (~0.5s/attempt, expensive to brute-force) |
| Authenticated encryption | GCM tag detects any tampering with ciphertext |

---

## Database schema

```sql
-- Verifier row (one row only) — used to detect wrong master passwords
passchain_master (kdf_salt, nonce, verifier)

-- Credentials
passchain_entries (service, username, kdf_salt, nonce, ciphertext)
--                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ composite primary key
```

`service` is stored in lowercase for consistent lookup. `username` is
case-sensitive. Neither is encrypted — treat them as non-secret metadata.