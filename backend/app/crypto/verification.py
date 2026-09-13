from __future__ import annotations

from app.crypto.commitments import create_share_commitment


def verify_share_commitment(
    *,
    share: str,
    expected_commitment: str,
    policy_id: str,
    trustee_id: str,
    epoch: int,
) -> bool:
    """Verify that a share matches the expected commitment."""
    actual_commitment = create_share_commitment(
        share,
        policy_id=policy_id,
        trustee_id=trustee_id,
        epoch=epoch,
    )

    return actual_commitment == expected_commitment