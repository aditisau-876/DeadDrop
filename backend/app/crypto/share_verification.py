
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Sequence

from cryptography.exceptions import InvalidTag

from app.crypto.commitments import create_share_commitment
from app.crypto.encryption import EncryptedPayload, decrypt
from app.crypto.secret_sharing import SecretShare, reconstruct_secret
from app.crypto.share_encryption import decrypt_share
from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)


@dataclass(frozen=True)
class VerifiedShare:
    trustee_id: str
    policy_id: str
    epoch: int
    value: str
    commitment: str


def _verify_share_value(
    *,
    value: str,
    commitment: str,
    policy_id: str,
    trustee_id: str,
    epoch: int,
) -> bool:
    if not validate_commitment_format(commitment):
        return False

    actual = create_share_commitment(
        value,
        policy_id=policy_id,
        trustee_id=trustee_id,
        epoch=epoch,
    )

    # Constant-time comparison avoids ordinary string comparison
    # for cryptographic commitment values.
    import hmac

    return hmac.compare_digest(
        actual.lower(),
        commitment.lower(),
    )


def decrypt_and_verify_share(
    encrypted_share: str,
    *,
    trustee_private_key: str,
    expected_commitment: str,
    expected_policy_id: str,
    expected_trustee_id: str,
    expected_epoch: int,
) -> VerifiedShare:
    """
    Decrypt one trustee share and verify its commitment.

    This function must run on the trusted recovery device.
    Never send the trustee private key or decrypted share
    to the DeadDrop API.
    """

    if not validate_commitment_format(expected_commitment):
        raise ValueError("Stored share commitment has an invalid format.")

    valid, reason = validate_share_envelope(
        encrypted_share,
        expected_policy_id=expected_policy_id,
        expected_trustee_id=expected_trustee_id,
        expected_epoch=expected_epoch,
    )

    if not valid:
        raise ValueError(f"Encrypted share envelope rejected: {reason}")

    try:
        share_value = decrypt_share(
            encrypted_share,
            trustee_private_key=trustee_private_key,
        )
    except (InvalidTag, ValueError, KeyError, TypeError) as exc:
        raise ValueError(
            "Share decryption failed. The encrypted share or private key is invalid."
        ) from exc
    except Exception as exc:
        raise ValueError("Unable to decrypt the trustee share.") from exc

    if not _verify_share_value(
        value=share_value,
        commitment=expected_commitment,
        policy_id=expected_policy_id,
        trustee_id=expected_trustee_id,
        epoch=expected_epoch,
    ):
        raise ValueError(
            "Share commitment verification failed. The decrypted share "
            "does not match its registered commitment."
        )

    return VerifiedShare(
        trustee_id=expected_trustee_id,
        policy_id=expected_policy_id,
        epoch=expected_epoch,
        value=share_value,
        commitment=expected_commitment.lower(),
    )


def reconstruct_verified_secret(
    shares: Sequence[VerifiedShare],
    *,
    threshold: int,
    expected_policy_id: str,
    expected_epoch: int,
) -> bytes:
    """
    Reconstruct the original secret using only verified shares.

    Every share is checked again before reconstruction.
    Duplicate trustees and mismatched policy/epoch values are rejected.
    """

    if threshold < 2:
        raise ValueError("Recovery threshold must be at least 2.")

    if len(shares) < threshold:
        raise ValueError(
            f"Not enough verified shares. Required: {threshold}; "
            f"received: {len(shares)}."
        )

    trustee_ids = [share.trustee_id for share in shares]

    if len(trustee_ids) != len(set(trustee_ids)):
        raise ValueError("Duplicate trustee shares are not allowed.")

    for share in shares:
        if share.policy_id != expected_policy_id:
            raise ValueError(
                "A share belongs to a different policy."
            )

        if share.epoch != expected_epoch:
            raise ValueError(
                "A share belongs to an outdated or unexpected epoch."
            )

        if not _verify_share_value(
            value=share.value,
            commitment=share.commitment,
            policy_id=share.policy_id,
            trustee_id=share.trustee_id,
            epoch=share.epoch,
        ):
            raise ValueError(
                f"Commitment verification failed for trustee {share.trustee_id}."
            )

    secret_shares = [
        SecretShare(
            index=index,
            value=share.value,
        )
        for index, share in enumerate(shares, start=1)
    ]

    try:
        return reconstruct_secret(
            secret_shares,
            threshold=threshold,
        )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            "The verified shares could not reconstruct the secret."
        ) from exc


def decrypt_recovered_payload(
    recovered_key: bytes,
    payload: EncryptedPayload,
) -> bytes:
    """
    Decrypt and authenticate the protected asset using the
    reconstructed AES-256 key.

    AES-GCM authentication detects an incorrect key or modified
    ciphertext, nonce, or associated data.
    """

    if len(recovered_key) != 32:
        raise ValueError(
            "The reconstructed key is not a valid AES-256 key."
        )

    try:
        associated_data = (
            base64.b64decode(payload.aad, validate=True)
            if payload.aad
            else None
        )
    except Exception as exc:
        raise ValueError(
            "The protected asset's associated data is invalid."
        ) from exc

    try:
        return decrypt(
            payload,
            recovered_key,
            associated_data=associated_data,
        )
    except (InvalidTag, ValueError) as exc:
        raise ValueError(
            "Asset authentication failed. The reconstructed key or "
            "encrypted asset data is incorrect or has been modified."
        ) from exc


def recover_and_decrypt_asset(
    shares: Sequence[VerifiedShare],
    *,
    threshold: int,
    expected_policy_id: str,
    expected_epoch: int,
    payload: EncryptedPayload,
) -> bytes:
    """
    Complete trusted-device recovery flow:

    1. Recheck trustee share commitments.
    2. Reconstruct the AES-256 key.
    3. Authenticate and decrypt the protected asset.

    The returned plaintext must remain on the trusted device.
    """

    recovered_key = reconstruct_verified_secret(
        shares,
        threshold=threshold,
        expected_policy_id=expected_policy_id,
        expected_epoch=expected_epoch,
    )

    return decrypt_recovered_payload(
        recovered_key,
        payload,
    )
