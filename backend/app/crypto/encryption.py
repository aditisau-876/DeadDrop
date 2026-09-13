from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32
NONCE_SIZE = 12


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: str
    nonce: str
    aad: str | None = None


def generate_key() -> bytes:
    """Generate a 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """Generate a fresh 96-bit nonce for AES-GCM."""
    return os.urandom(NONCE_SIZE)


def encrypt(
    plaintext: bytes,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> EncryptedPayload:
    """
    Encrypt plaintext using AES-256-GCM.

    The nonce must never be reused with the same key.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = generate_nonce()

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        associated_data,
    )

    return EncryptedPayload(
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
        aad=(
            base64.b64encode(associated_data).decode("ascii")
            if associated_data is not None
            else None
        ),
    )


def decrypt(
    payload: EncryptedPayload,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate an AES-256-GCM payload."""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = base64.b64decode(payload.nonce)
    ciphertext = base64.b64decode(payload.ciphertext)

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid AES-GCM nonce.")

    aes = AESGCM(key)

    try:
        return aes.decrypt(
            nonce,
            ciphertext,
            associated_data,
        )
    except InvalidTag as exc:
        raise ValueError(
            "Decryption failed: authentication tag is invalid."
        ) from exc


def key_to_base64(key: bytes) -> str:
    """Serialize an AES key for controlled transport/storage."""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    return base64.b64encode(key).decode("ascii")


def key_from_base64(value: str) -> bytes:
    """Deserialize a base64 encoded AES-256 key."""
    key = base64.b64decode(value)

    if len(key) != KEY_SIZE:
        raise ValueError("Invalid AES-256 key.")

    return key