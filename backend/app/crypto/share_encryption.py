from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
KEY_SIZE = 32


@dataclass(frozen=True)
class TrusteeKeyPair:
    private_key: str
    public_key: str


def generate_trustee_key_pair() -> TrusteeKeyPair:
    """
    Generate an X25519 key pair for a trustee.

    The private key must remain with the trustee.
    The public key can be registered with DeadDrop.
    """

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()

    return TrusteeKeyPair(
        private_key=base64.b64encode(
            private_bytes
        ).decode("ascii"),
        public_key=base64.b64encode(
            public_bytes
        ).decode("ascii"),
    )


def _derive_share_key(
    shared_secret: bytes,
    *,
    context: bytes,
) -> bytes:
    """
    Derive an AES-256 key from an X25519 shared secret.
    """

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"DeadDrop/share-encryption/" + context,
    ).derive(shared_secret)


def encrypt_share_for_trustee(
    share: str,
    *,
    trustee_public_key: str,
    policy_id: str,
    trustee_id: str,
    epoch: int,
) -> str:
    """
    Encrypt one secret share for a trustee.

    The returned value is safe to store in the database,
    assuming the trustee private key remains private.
    """

    if not share:
        raise ValueError("Share cannot be empty.")

    if not trustee_public_key:
        raise ValueError(
            "Trustee public key is required."
        )

    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = (
        ephemeral_private.public_key()
    )

    trustee_public = X25519PublicKey.from_public_bytes(
        base64.b64decode(trustee_public_key)
    )

    shared_secret = ephemeral_private.exchange(
        trustee_public
    )

    context = (
        f"{policy_id}:{trustee_id}:{epoch}"
    ).encode("utf-8")

    encryption_key = _derive_share_key(
        shared_secret,
        context=context,
    )

    nonce = os.urandom(NONCE_SIZE)

    aad = context

    ciphertext = AESGCM(
        encryption_key
    ).encrypt(
        nonce,
        share.encode("utf-8"),
        aad,
    )

    envelope = {
        "version": 1,
        "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
        "ephemeral_public_key": base64.b64encode(
            ephemeral_public.public_bytes_raw()
        ).decode("ascii"),
        "nonce": base64.b64encode(
            nonce
        ).decode("ascii"),
        "ciphertext": base64.b64encode(
            ciphertext
        ).decode("ascii"),
        "policy_id": policy_id,
        "trustee_id": trustee_id,
        "epoch": epoch,
    }

    return base64.b64encode(
        json.dumps(
            envelope,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")


def decrypt_share(
    encrypted_share: str,
    *,
    trustee_private_key: str,
) -> str:
    """
    Decrypt a share using the trustee's private X25519 key.
    """

    raw = base64.b64decode(
        encrypted_share
    )

    envelope = json.loads(
        raw.decode("utf-8")
    )

    if envelope.get("version") != 1:
        raise ValueError(
            "Unsupported encrypted-share version."
        )

    ephemeral_public = X25519PublicKey.from_public_bytes(
        base64.b64decode(
            envelope["ephemeral_public_key"]
        )
    )

    private_key = X25519PrivateKey.from_private_bytes(
        base64.b64decode(
            trustee_private_key
        )
    )

    shared_secret = private_key.exchange(
        ephemeral_public
    )

    context = (
        f"{envelope['policy_id']}:"
        f"{envelope['trustee_id']}:"
        f"{envelope['epoch']}"
    ).encode("utf-8")

    encryption_key = _derive_share_key(
        shared_secret,
        context=context,
    )

    nonce = base64.b64decode(
        envelope["nonce"]
    )

    ciphertext = base64.b64decode(
        envelope["ciphertext"]
    )

    plaintext = AESGCM(
        encryption_key
    ).decrypt(
        nonce,
        ciphertext,
        context,
    )

    return plaintext.decode("utf-8")