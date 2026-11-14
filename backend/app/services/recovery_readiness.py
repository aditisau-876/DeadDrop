
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.models.share import EncryptedShare
from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)


def calculate_recovery_readiness(
    db: Session,
    asset: ProtectedAsset,
) -> dict:
    policy = db.get(Policy, asset.policy_id)

    if policy is None:
        return {
            "asset_id": asset.id,
            "ready_for_recovery": False,
            "reason": "Associated policy does not exist.",
            "threshold": asset.threshold,
            "valid_structural_shares": 0,
            "assigned_trustees": 0,
            "missing_trustees": [],
            "invalid_shares": [],
            "commitments_present": False,
            "cryptographic_proof_verified": False,
        }

    assigned_trustees = set(policy.trustee_ids or [])

    shares = db.scalars(
        select(EncryptedShare).where(
            EncryptedShare.asset_id == asset.id,
            EncryptedShare.epoch == asset.epoch,
        )
    ).all()

    shares_by_trustee = {
        share.trustee_id: share
        for share in shares
    }

    valid_trustees: set[str] = set()
    invalid_shares: list[dict] = []

    for share in shares:
        if share.trustee_id not in assigned_trustees:
            invalid_shares.append({
                "trustee_id": share.trustee_id,
                "reason": "Trustee is not assigned to this policy.",
            })
            continue

        if not validate_commitment_format(share.commitment):
            invalid_shares.append({
                "trustee_id": share.trustee_id,
                "reason": "Invalid commitment format.",
            })
            continue

        valid, reason = validate_share_envelope(
            share.encrypted_share,
            expected_policy_id=policy.id,
            expected_trustee_id=share.trustee_id,
            expected_epoch=asset.epoch,
        )

        if not valid:
            invalid_shares.append({
                "trustee_id": share.trustee_id,
                "reason": reason,
            })
            continue

        valid_trustees.add(share.trustee_id)

    missing_trustees = sorted(
        assigned_trustees - valid_trustees
    )

    threshold_available = (
        len(valid_trustees) >= asset.threshold
    )

    policy_current = (
        policy.active
        and policy.epoch == asset.epoch
    )

    ready = threshold_available and policy_current

    if not policy.active:
        reason = "The associated policy is inactive."
    elif policy.epoch != asset.epoch:
        reason = "Asset shares belong to an outdated policy epoch."
    elif not threshold_available:
        reason = "Not enough structurally valid encrypted shares."
    else:
        reason = (
            "The required number of structurally valid encrypted "
            "share packages is available."
        )

    return {
        "asset_id": asset.id,
        "ready_for_recovery": ready,
        "reason": reason,
        "threshold": asset.threshold,
        "valid_structural_shares": len(valid_trustees),
        "assigned_trustees": len(assigned_trustees),
        "missing_trustees": missing_trustees,
        "invalid_shares": invalid_shares,
        "commitments_present": (
            len(valid_trustees) >= asset.threshold
        ),
        "cryptographic_proof_verified": False,
        "policy_epoch": policy.epoch,
        "asset_epoch": asset.epoch,
    }
