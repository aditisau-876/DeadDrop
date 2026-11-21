
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)
from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.models.share import EncryptedShare
from app.models.trustee import Trustee


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

    if not assigned_trustees:
        return {
            "asset_id": asset.id,
            "ready_for_recovery": False,
            "reason": "Policy has no assigned trustees.",
            "threshold": asset.threshold,
            "valid_structural_shares": 0,
            "assigned_trustees": 0,
            "missing_trustees": [],
            "invalid_shares": [],
            "commitments_present": False,
            "cryptographic_proof_verified": False,
        }

    trustees = db.scalars(
        select(Trustee).where(
            Trustee.id.in_(assigned_trustees)
        )
    ).all()

    active_trustee_ids = {
        trustee.id
        for trustee in trustees
        if trustee.active
    }

    shares = db.scalars(
        select(EncryptedShare).where(
            EncryptedShare.asset_id == asset.id,
            EncryptedShare.epoch == asset.epoch,
        )
    ).all()

    valid_trustees: set[str] = set()
    invalid_shares: list[dict] = []
    seen_trustees: set[str] = set()

    for share in shares:
        trustee_id = share.trustee_id

        if trustee_id in seen_trustees:
            invalid_shares.append({
                "trustee_id": trustee_id,
                "reason": "Duplicate share record.",
            })
            continue

        seen_trustees.add(trustee_id)

        if trustee_id not in assigned_trustees:
            invalid_shares.append({
                "trustee_id": trustee_id,
                "reason": "Trustee is not assigned to this policy.",
            })
            continue

        if trustee_id not in active_trustee_ids:
            invalid_shares.append({
                "trustee_id": trustee_id,
                "reason": "Trustee is inactive or missing.",
            })
            continue

        if not validate_commitment_format(share.commitment):
            invalid_shares.append({
                "trustee_id": trustee_id,
                "reason": "Invalid commitment format.",
            })
            continue

        valid, reason = validate_share_envelope(
            share.encrypted_share,
            expected_policy_id=policy.id,
            expected_trustee_id=trustee_id,
            expected_epoch=asset.epoch,
        )

        if not valid:
            invalid_shares.append({
                "trustee_id": trustee_id,
                "reason": reason,
            })
            continue

        valid_trustees.add(trustee_id)

    missing_trustees = sorted(
        assigned_trustees - valid_trustees
    )

    threshold_available = (
        asset.threshold >= 2
        and len(valid_trustees) >= asset.threshold
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
        reason = (
            "Not enough structurally valid encrypted shares "
            "are available."
        )
    else:
        reason = (
            "The required number of structurally valid encrypted "
            "share packages is available. Actual share decryption "
            "and reconstruction have not been verified."
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
