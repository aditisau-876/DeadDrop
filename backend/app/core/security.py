from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    if length <= 0:
        raise ValueError("Length must be greater than zero.")

    return secrets.token_bytes(length)


def generate_nonce(length: int = 32) -> str:
    """Generate a cryptographically secure hexadecimal nonce."""
    if length <= 0:
        raise ValueError("Length must be greater than zero.")

    return secrets.token_hex(length)


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest as a hexadecimal string."""
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Return SHA-256 digest as raw bytes."""
    return hashlib.sha256(data).digest()


def secure_compare(left: str, right: str) -> bool:
    """Constant-time comparison for sensitive strings."""
    return hmac.compare_digest(left, right)


def generate_identifier() -> str:
    """Generate a random application-level identifier."""
    return secrets.token_urlsafe(24)