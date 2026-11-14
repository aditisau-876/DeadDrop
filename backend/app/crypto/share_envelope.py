
from __future__ import annotations

import base64
import json
import re
from typing import Any


COMMITMENT_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def validate_share_envelope(
    encrypted_share: str,
    *,
    expected_policy_id: str,
    expected_trustee_id: str,
    expected_epoch: int,
) -> tuple[bool, str]:
    """
    Validate the encrypted envelope's structure and identity metadata.

    This does NOT decrypt the share or prove that the underlying
    Shamir share is mathematically valid.
    """

    try:
        raw = base64.b64decode(encrypted_share, validate=True)
        envelope: Any = json.loads(raw.decode("utf-8"))

        if not isinstance(envelope, dict):
            return False, "Envelope must be a JSON object."

        required_fields = {
            "version",
            "algorithm",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
            "policy_id",
            "trustee_id",
            "epoch",
        }

        missing = required_fields - envelope.keys()

        if missing:
            return False, "Envelope is missing required fields."

        if envelope["policy_id"] != expected_policy_id:
            return False, "Policy ID mismatch."

        if envelope["trustee_id"] != expected_trustee_id:
            return False, "Trustee ID mismatch."

        if envelope["epoch"] != expected_epoch:
            return False, "Envelope epoch mismatch."

        if not isinstance(envelope["version"], int):
            return False, "Invalid envelope version."

        for field in (
            "algorithm",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
        ):
            if not isinstance(envelope[field], str) or not envelope[field]:
                return False, f"Invalid {field}."

        return True, "Envelope structure and metadata are valid."

    except (
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
    ):
        return False, "Encrypted share is not a valid encoded envelope."


def validate_commitment_format(commitment: str) -> bool:
    """Check only that the commitment is a 32-byte SHA-256 hex digest."""

    return bool(COMMITMENT_PATTERN.fullmatch(commitment or ""))
