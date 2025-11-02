#!/usr/bin/env python3
"""
Usage:
  python password_manager.py init
  python password_manager.py add <name> 
  python password_manager.py get <name>
  python password_manager.py list
  python password_manager.py rm <name>
"""

import argparse
import base64
import json
import os
import getpass
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

VAULT_DIR = Path.home() / ".pyvault"
SALT_FILE = VAULT_DIR / "salt"
VAULT_FILE = VAULT_DIR / "vault.bin"
KDF_ITERS = 390_000

def ensure_vault_dir():
    VAULT_DIR.mkdir(mode=0o700, exist_ok=True)

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def init_vault():
    ensure_vault_dir()
    if SALT_FILE.exists() or VAULT_FILE.exists():
        print("Vault already exists (use a different directory or remove ~/.pyvault).")
        return
    password = getpass.getpass("Create master password: ").encode()
    confirm = getpass.getpass("Confirm: ").encode()
    if password != confirm:
        print("Passwords do not match.")
        return
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    empty = json.dumps({"entries": {}}).encode()
    token = f.encrypt(empty)
    SALT_FILE.write_bytes(base64.b64encode(salt))
    VAULT_FILE.write_bytes(token)
    os.chmod(SALT_FILE, 0o600)
    os.chmod(VAULT_FILE, 0o600)
    print("Vault initialized at ~/.pyvault")

def load_vault():
    if not SALT_FILE.exists() or not VAULT_FILE.exists():
        raise SystemExit("Vault not initialized. Run `init` first.")
    salt = base64.b64decode(SALT_FILE.read_bytes())
    password = getpass.getpass("Master password: ").encode()
    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        blob = VAULT_FILE.read_bytes()
        data = json.loads(f.decrypt(blob))
    except Exception:
        raise SystemExit("Failed to decrypt vault — incorrect password or corrupted vault.")
    return f, data

def save_vault(f: Fernet, data: dict):
    blob = f.encrypt(json.dumps(data).encode())
    VAULT_FILE.write_bytes(blob)

def cmd_add(name):
    f, data = load_vault()
    username = input("Username/email (optional): ").strip()
    pwd = getpass.getpass("Password (leave empty to generate): ")
    if not pwd:
        import secrets, string
        pwd = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()-_") for _ in range(16))
        print("Generated password:", pwd)
    notes = input("Notes (optional): ")
    data["entries"][name] = {"username": username, "password": pwd, "notes": notes}
    save_vault(f, data)
    print(f"Saved {name}.")

def cmd_get(name):
    f, data = load_vault()
    entry = data["entries"].get(name)
    if not entry:
        print("No entry named", name)
        return
    print("Service:", name)
    print("Username:", entry.get("username", ""))
    print("Password:", entry.get("password", ""))
    if entry.get("notes"):
        print("Notes:", entry["notes"])

def cmd_list():
    f, data = load_vault()
    names = sorted(data["entries"].keys())
    if not names:
        print("No entries.")
        return
    for n in names:
        print("-", n)

def cmd_rm(name):
    f, data = load_vault()
    if name in data["entries"]:
        confirm = input(f"Delete {name}? [y/N]: ").lower()
        if confirm == "y":
            del data["entries"][name]
            save_vault(f, data)
            print("Deleted.")
        else:
            print("Cancelled.")
    else:
        print("No such entry.")

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("init")
    p_add = sub.add_parser("add"); p_add.add_argument("name")
    p_get = sub.add_parser("get"); p_get.add_argument("name")
    sub.add_parser("list")
    p_rm = sub.add_parser("rm"); p_rm.add_argument("name")
    args = parser.parse_args()

    if args.cmd == "init":
        init_vault()
    elif args.cmd == "add":
        cmd_add(args.name)
    elif args.cmd == "get":
        cmd_get(args.name)
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "rm":
        cmd_rm(args.name)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
