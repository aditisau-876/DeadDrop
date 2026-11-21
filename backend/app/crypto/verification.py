
from __future__ import annotations

import hmac

from app.crypto.commitments import create_share_commitment
from app.crypto.share_envelope import validate_commitment_format


def verify_share_commitment(
    *,
    share: str,
    expected_commitment: str,
    policy_id: str,
    trustee_id: str,
    epoch: int,
) -> bool:
    """
    Verify that a plaintext share matches its SHA-256 commitment.

    Comparison is constant-time and malformed commitments
    are rejected.
    """

    if not share:
        return False

    if not validate_commitment_format(expected_commitment):
        return False

    try:
        actual_commitment = create_share_commitment(
            share,
            policy_id=policy_id,
            trustee_id=trustee_id,
            epoch=epoch,
        )
    except ValueError:
        return False

    return hmac.compare_digest(
        actual_commitment.lower(),
        expected_commitment.lower(),
    )
