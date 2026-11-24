from __future__ import annotations

import base64
import json
import os
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


def _gf256_mul(a: int, b: int) -> int:
    result = 0
    left = a & 0xFF
    right = b & 0xFF
    while right:
        if right & 1:
            result ^= left
        high = left & 0x80
        left = (left << 1) & 0xFF
        if high:
            left ^= 0x1B
        right >>= 1
    return result & 0xFF


def _gf256_pow(value: int, exponent: int) -> int:
    result = 1
    base = value & 0xFF
    while exponent:
        if exponent & 1:
            result = _gf256_mul(result, base)
        base = _gf256_mul(base, base)
        exponent >>= 1
    return result


def split_secret_gf256(
    secret: bytes,
    *,
    threshold: int,
    share_count: int,
) -> list[SecretShare]:
    """Split raw bytes using DeadDrop's browser-compatible GF(256) scheme."""
    if not secret:
        raise ValueError("Secret cannot be empty.")
    if threshold < 2 or threshold > share_count or share_count > 16:
        raise ValueError("Invalid threshold or share count.")
    coefficients = [os.urandom(threshold - 1) for _ in secret]
    shares: list[SecretShare] = []
    for x in range(1, share_count + 1):
        y = bytearray(len(secret))
        for index, secret_byte in enumerate(secret):
            value = secret_byte
            power = x
            for coefficient in coefficients[index]:
                value ^= _gf256_mul(coefficient, power)
                power = _gf256_mul(power, x)
            y[index] = value
        encoded = json.dumps(
            {
                "scheme": "deaddrop-gf256-v1",
                "x": x,
                "y": base64.b64encode(bytes(y)).decode("ascii"),
            },
            separators=(",", ":"),
        )
        shares.append(SecretShare(index=x, value=encoded))
    return shares


def _reconstruct_gf256(shares: list[SecretShare], threshold: int) -> bytes:
    parsed: list[tuple[int, bytes]] = []
    for share in shares[:threshold]:
        try:
            item = json.loads(share.value)
            if item.get("scheme") != "deaddrop-gf256-v1":
                raise ValueError
            x = item.get("x")
            y = base64.b64decode(item.get("y", ""), validate=True)
            if not isinstance(x, int) or isinstance(x, bool) or not 1 <= x <= 255 or not y:
                raise ValueError
            parsed.append((x, y))
        except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid DeadDrop GF(256) share.") from exc
    if len({x for x, _ in parsed}) != len(parsed):
        raise ValueError("Duplicate GF(256) share coordinates.")
    length = len(parsed[0][1])
    if any(len(y) != length for _, y in parsed):
        raise ValueError("GF(256) share lengths do not match.")
    secret = bytearray(length)
    for i, (xi, yi) in enumerate(parsed):
        coefficient = 1
        for j, (xj, _) in enumerate(parsed):
            if i == j:
                continue
            denominator = xi ^ xj
            if denominator == 0:
                raise ValueError("Duplicate GF(256) share coordinates.")
            coefficient = _gf256_mul(
                coefficient,
                _gf256_mul(xj, _gf256_pow(denominator, 254)),
            )
        for index, byte in enumerate(yi):
            secret[index] ^= _gf256_mul(byte, coefficient)
    return bytes(secret)


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

    # Browser-created assets use the explicitly versioned GF(256) format.
    # Existing SLIP-0039 shares remain supported for older protected assets.
    try:
        first = json.loads(selected_shares[0].value)
    except (ValueError, TypeError, json.JSONDecodeError):
        first = None
    if isinstance(first, dict) and first.get("scheme") == "deaddrop-gf256-v1":
        return _reconstruct_gf256(selected_shares, threshold)

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