from __future__ import annotations

import base64
import secrets
import string
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken


def _ensure_fernet_key(key: str) -> bytes:
    # Fernet expects 32 urlsafe base64-encoded bytes
    raw = key.encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(raw)
    except Exception as e:  # noqa: BLE001
        raise ValueError("ENCRYPTION_KEY must be urlsafe base64") from e
    if len(decoded) != 32:
        raise ValueError("ENCRYPTION_KEY must decode to exactly 32 bytes")
    return raw


@dataclass(frozen=True)
class CryptoBox:
    fernet: Fernet

    @classmethod
    def from_key(cls, key: str) -> "CryptoBox":
        return cls(Fernet(_ensure_fernet_key(key)))

    def encrypt(self, s: str | None) -> str | None:
        if s is None:
            return None
        token = self.fernet.encrypt(s.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, token: str | None) -> str | None:
        if token is None:
            return None
        try:
            raw = self.fernet.decrypt(token.encode("utf-8"))
            return raw.decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Invalid encrypted payload (wrong key?)") from e


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    # Avoid punctuation to make it shell/env friendly
    return "".join(secrets.choice(alphabet) for _ in range(length))
