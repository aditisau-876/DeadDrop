from __future__ import annotations

from dataclasses import dataclass

from shamir_mnemonic import (
    combine_mnemonics,
    generate_mnemonics,
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

    if not secret:
        raise ValueError(
            "Secret cannot be empty."
        )

    if len(secret) < 16:
        raise ValueError(
            "Secret must contain at least 16 bytes."
        )

    if len(secret) % 2 != 0:
        raise ValueError(
            "Secret must have an even number of bytes."
        )

    if threshold < 2:
        raise ValueError(
            "Threshold must be at least 2."
        )

    if share_count < threshold:
        raise ValueError(
            "Share count cannot be smaller than threshold."
        )

    if share_count > 16:
        raise ValueError(
            "Maximum share count is 16."
        )

    mnemonics = generate_mnemonics(
        group_threshold=1,
        groups=[
            (
                threshold,
                share_count,
            )
        ],
        master_secret=secret,
    )

    shares = [
        SecretShare(
            index=index + 1,
            value=value,
        )
        for index, value in enumerate(
            mnemonics[0]
        )
    ]

    return SharedSecret(
        group=1,
        threshold=threshold,
        shares=shares,
    )


def reconstruct_secret(
    shares: list[SecretShare],
    *,
    threshold: int | None = None,
) -> bytes:

    if not shares:
        raise ValueError(
            "At least one share is required."
        )

    if threshold is None:
        # When no threshold is explicitly supplied,
        # use the number of provided shares.
        #
        # This supports the common case where the caller
        # has already selected exactly the required shares.
        threshold = len(shares)

    if threshold < 2:
        raise ValueError(
            "Threshold must be at least 2."
        )

    if len(shares) < threshold:
        raise ValueError(
            "Not enough shares to reconstruct secret."
        )

    selected_shares = shares[:threshold]

    try:
        return combine_mnemonics(
            [
                share.value
                for share in selected_shares
            ]
        )

    except Exception as exc:
        raise ValueError(
            "Secret reconstruction failed."
        ) from exc