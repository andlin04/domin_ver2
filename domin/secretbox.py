"""Two-factor secrets encrypted at rest: Fernet (AES-128-CBC + HMAC-SHA256) with a key kept outside the database.

The key file (DOMIN_TOTP_KEY, default /etc/domin/totp.key, root:domin 0640; install.sh and update.sh create it when
missing and never overwrite it) holds one urlsafe-base64 Fernet key. Stored values carry the prefix "f1:", so a
value without it is a plaintext one from before encryption (migrate() encrypts those). The key is read on each use,
never cached: a missing or wrong key makes decrypt() raise KeyUnavailable, and the callers fail closed (no TOTP
code is accepted) instead of crashing. Protects copies of the database (backups, rollback copies); not a
compromised domin process or root, which can read the key."""
from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import totp_key_path as key_path

PREFIX = "f1:"


class KeyUnavailable(Exception):
    """The key file is missing, unreadable or malformed, or a value was encrypted with another key."""


def new_key() -> bytes:
    return base64.urlsafe_b64encode(secrets.token_bytes(32))


def load(path: Path | None = None) -> Fernet:
    path = path or key_path()
    try:
        return Fernet(path.read_bytes().strip())
    except OSError as e:
        raise KeyUnavailable(f"key file {path}: {e.strerror or type(e).__name__}") from None
    except ValueError:
        raise KeyUnavailable(f"key file {path}: not a Fernet key") from None


def is_encrypted(value: str) -> bool:
    return value.startswith(PREFIX)


def encrypt(plain: str, key: Fernet | None = None) -> str:
    return PREFIX + (key or load()).encrypt(plain.encode()).decode()


def decrypt(value: str, key: Fernet | None = None) -> str:
    """The plaintext of a stored value; a value without the prefix is returned as it is (not yet migrated)."""
    if not is_encrypted(value):
        return value
    key = key or load()
    try:
        return key.decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        raise KeyUnavailable(f"key file {key_path()}: does not decrypt the stored value (wrong key)") from None


def write_key(path: Path, key: bytes) -> None:
    """Write a key file (mode 0640): a new file, or an existing one the caller may write (its owner stays)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "wb") as f:
        f.write(key + b"\n")
