from __future__ import annotations

import base64

from app.crypto.encryption import (
    EncryptedPayload,
    encrypt,
    generate_key,
)


def encrypt_secret(
    plaintext: bytes,
    *,
    associated_data: bytes | None = None,
) -> tuple[EncryptedPayload, bytes]:
    """
    Encrypt a secret using AES-256-GCM.

    Returns:
        encrypted payload
        AES-256 key

    IMPORTANT:
    The caller is responsible for protecting/splitting the key.
    This function does not persist the key anywhere.
    """

    key = generate_key()

    payload = encrypt(
        plaintext,
        key,
        associated_data=associated_data,
    )

    return payload, key


def payload_to_dict(
    payload: EncryptedPayload,
) -> dict[str, str | None]:
    return {
        "ciphertext": payload.ciphertext,
        "nonce": payload.nonce,
        "aad": payload.aad,
    }