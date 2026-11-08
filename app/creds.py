"""Local, encrypted credential storage for authenticated scanning.

Credentials never go into the database or logs in clear text, and are never hardcoded in this
codebase. They're encrypted at rest with a key file (data/.credkey) generated on first use and
kept out of git by .gitignore. Treat data/.credkey and data/credentials.enc as sensitive files:
anyone with both can read the stored credentials.
"""
import json
import os

from cryptography.fernet import Fernet

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
KEY_PATH = os.path.join(DATA_DIR, ".credkey")
STORE_PATH = os.path.join(DATA_DIR, "credentials.enc")


def _fernet():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as f:
            f.write(Fernet.generate_key())
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass  # chmod is a no-op on Windows; NTFS permissions apply instead
    return Fernet(open(KEY_PATH, "rb").read())


def list_saved():
    """Names only, never the secrets."""
    if not os.path.exists(STORE_PATH):
        return []
    try:
        data = json.loads(_fernet().decrypt(open(STORE_PATH, "rb").read()))
        return sorted(data.keys())
    except Exception:
        return []


def save(name, cred):
    """cred: {protocol, username, password?, key_path?, port?}. Overwrites any existing entry with this name."""
    data = {}
    if os.path.exists(STORE_PATH):
        try:
            data = json.loads(_fernet().decrypt(open(STORE_PATH, "rb").read()))
        except Exception:
            data = {}
    data[name] = cred
    enc = _fernet().encrypt(json.dumps(data).encode())
    with open(STORE_PATH, "wb") as f:
        f.write(enc)
    try:
        os.chmod(STORE_PATH, 0o600)
    except OSError:
        pass


def get(name):
    if not os.path.exists(STORE_PATH):
        return None
    try:
        data = json.loads(_fernet().decrypt(open(STORE_PATH, "rb").read()))
    except Exception:
        return None
    return data.get(name)


def delete(name):
    if not os.path.exists(STORE_PATH):
        return
    try:
        data = json.loads(_fernet().decrypt(open(STORE_PATH, "rb").read()))
    except Exception:
        return
    data.pop(name, None)
    with open(STORE_PATH, "wb") as f:
        f.write(_fernet().encrypt(json.dumps(data).encode()))
