from __future__ import annotations

from dataclasses import dataclass

from shamir_mnemonic import (
    generate_mnemonics,
    combine_mnemonics,
)


@dataclass(frozen=True)
class SecretShare:
    index: int
    value: str


@dataclass(frozen=True)
class SharedSecret:
    group: int
    threshold: int
    shares: list[SecretShare]


def split_secret(
    secret: bytes,
    *,
    threshold: int,
    share_count: int,
) -> SharedSecret:
    """
    Split a secret into Shamir-based mnemonic shares.

    NOTE:
    This provides the threshold primitive. DeadDrop's generalized
    policy engine will sit above this layer.
    """
    if not secret:
        raise ValueError("Secret cannot be empty.")

    if threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    if share_count < threshold:
        raise ValueError(
            "Share count cannot be smaller than threshold."
        )

    if share_count > 16:
        raise ValueError(
            "This implementation supports at most 16 shares."
        )

    mnemonics = generate_mnemonics(
        group_threshold=1,
        groups=[
            (
                threshold,
                share_count,
                secret,
            )
        ],
    )

    shares = [
        SecretShare(
            index=index + 1,
            value=value,
        )
        for index, value in enumerate(mnemonics[0])
    ]

    return SharedSecret(
        group=1,
        threshold=threshold,
        shares=shares,
    )


def reconstruct_secret(
    shares: list[SecretShare],
) -> bytes:
    """Reconstruct the original secret from sufficient shares."""
    if not shares:
        raise ValueError("At least one share is required.")

    mnemonics = [share.value for share in shares]

    try:
        return combine_mnemonics(mnemonics)
    except Exception as exc:
        raise ValueError(
            "Secret reconstruction failed."
        ) from exc