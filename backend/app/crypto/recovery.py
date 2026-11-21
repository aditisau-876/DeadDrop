
from __future__ import annotations

from dataclasses import dataclass

from app.crypto.commitments import create_share_commitment
from app.crypto.secret_sharing import (
    SecretShare,
    SharedSecret,
    reconstruct_secret,
    split_secret,
)
from app.crypto.share_encryption import encrypt_share_for_trustee


@dataclass(frozen=True)
class PreparedShare:
    trustee_id: str
    share_index: int
    commitment: str
    encrypted_share: str
    epoch: int


@dataclass(frozen=True)
class PreparedRecoveryMaterial:
    shared_secret: SharedSecret
    shares: list[PreparedShare]


def prepare_recovery_material(
    secret: bytes,
    *,
    threshold: int,
    trustees: list[dict[str, str]],
    policy_id: str,
    epoch: int,
) -> PreparedRecoveryMaterial:
    """
    Split a secret and encrypt one share for each trustee.

    Each trustee entry must contain:
        {
            "id": "...",
            "public_key": "..."
        }

    Plaintext shares are returned only to the calling process.
    They must never be persisted by the backend.
    """

    if not policy_id:
        raise ValueError("Policy ID is required.")

    if epoch < 1:
        raise ValueError("Epoch must be at least 1.")

    if not trustees:
        raise ValueError("At least one trustee is required.")

    if threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    if threshold > len(trustees):
        raise ValueError(
            "Threshold cannot exceed trustee count."
        )

    trustee_ids = [trustee.get("id") for trustee in trustees]

    if any(not trustee_id for trustee_id in trustee_ids):
        raise ValueError("Every trustee must have an ID.")

    if len(trustee_ids) != len(set(trustee_ids)):
        raise ValueError("Duplicate trustee IDs are not allowed.")

    for trustee in trustees:
        if not trustee.get("public_key"):
            raise ValueError(
                f"Trustee {trustee['id']} has no public key."
            )

    shared_secret = split_secret(
        secret,
        threshold=threshold,
        share_count=len(trustees),
    )

    prepared: list[PreparedShare] = []

    for trustee, share in zip(
        trustees,
        shared_secret.shares,
    ):
        trustee_id = trustee["id"]
        public_key = trustee["public_key"]

        commitment = create_share_commitment(
            share.value,
            policy_id=policy_id,
            trustee_id=trustee_id,
            epoch=epoch,
        )

        encrypted_share = encrypt_share_for_trustee(
            share.value,
            trustee_public_key=public_key,
            policy_id=policy_id,
            trustee_id=trustee_id,
            epoch=epoch,
        )

        prepared.append(
            PreparedShare(
                trustee_id=trustee_id,
                share_index=share.index,
                commitment=commitment,
                encrypted_share=encrypted_share,
                epoch=epoch,
            )
        )

    return PreparedRecoveryMaterial(
        shared_secret=shared_secret,
        shares=prepared,
    )


def reconstruct_from_shares(
    shares: list[SecretShare],
    *,
    threshold: int,
) -> bytes:
    """
    Reconstruct the original secret from at least `threshold`
    valid shares.

    This function belongs on the trusted recovery client.
    The backend must not receive plaintext shares.
    """

    if threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    if len(shares) < threshold:
        raise ValueError(
            "Not enough shares to reconstruct the secret."
        )

    return reconstruct_secret(
        shares,
        threshold=threshold,
    )
