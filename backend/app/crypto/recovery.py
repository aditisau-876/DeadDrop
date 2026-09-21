from __future__ import annotations

from dataclasses import dataclass

from app.crypto.commitments import (
    create_share_commitment,
)
from app.crypto.secret_sharing import (
    SecretShare,
    SharedSecret,
    reconstruct_secret,
    split_secret,
)
from app.crypto.share_encryption import (
    encrypt_share_for_trustee,
)


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
    Split a secret into shares and encrypt each share
    for its assigned trustee.

    `trustees` must contain:

        {
            "id": "...",
            "public_key": "..."
        }

    The plaintext shares are returned only to the
    calling process and are not persisted here.
    """

    if not trustees:
        raise ValueError(
            "At least one trustee is required."
        )

    if threshold > len(trustees):
        raise ValueError(
            "Threshold cannot exceed trustee count."
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

        if not public_key:
            raise ValueError(
                f"Trustee {trustee_id} has no public key."
            )

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
) -> bytes:
    """
    Reconstruct the original secret from valid shares.

    This function should ultimately execute on the
    recovery client, not the normal backend.
    """

    return reconstruct_secret(shares)