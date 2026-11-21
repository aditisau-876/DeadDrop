
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    generate_identifier,
    require_roles,
    ensure_owner_or_admin,
)
from app.db.database import get_db
from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.models.recovery import RecoveryRequest
from app.models.share import EncryptedShare
from app.models.trustee import Trustee
from app.schemas.share_rotation import (
    ShareRotationRequest,
    ShareRotationResponse,
)
from app.services.recovery_lifecycle import (
    expire_recovery_if_needed,
)
from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)


router = APIRouter(
    prefix="/api/policies",
    tags=["Share Epoch Rotation"],
)


@router.post(
    "/{policy_id}/rotate-shares",
    response_model=ShareRotationResponse,
)
def rotate_policy_shares(
    policy_id: str,
    data: ShareRotationRequest,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    """
    Re-issue encrypted trustee shares for every protected asset
    under a policy and atomically advance the policy epoch.

    Plaintext keys and shares must be generated and retained
    on the trusted client. The backend only receives encrypted
    share envelopes and commitments.
    """

    # Lock the policy so recovery creation, policy updates,
    # and another rotation cannot concurrently change its state.
    policy = db.scalar(
        select(Policy)
        .where(Policy.id == policy_id)
        .with_for_update()
    )

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(user, policy.owner_user_id)

    if not policy.active:
        raise HTTPException(
            status_code=409,
            detail="An inactive policy cannot rotate its shares.",
        )

    if policy.epoch != data.expected_epoch:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "The policy epoch has changed.",
                "expected_epoch": data.expected_epoch,
                "current_epoch": policy.epoch,
            },
        )

    previous_epoch = policy.epoch
    new_epoch = previous_epoch + 1

    assigned_trustee_ids = set(policy.trustee_ids or [])

    if len(assigned_trustee_ids) < 2:
        raise HTTPException(
            status_code=409,
            detail="The policy needs at least two assigned trustees.",
        )

    # Lock active recovery requests and expire overdue ones.
    active_recoveries = db.scalars(
        select(RecoveryRequest)
        .where(
            RecoveryRequest.policy_id == policy.id,
            RecoveryRequest.status.in_(["PENDING", "APPROVED"]),
        )
        .with_for_update()
    ).all()

    now = datetime.utcnow()

    for recovery in active_recoveries:
        expire_recovery_if_needed(recovery, now)

    still_active = [
        recovery
        for recovery in active_recoveries
        if recovery.status in {"PENDING", "APPROVED"}
    ]

    if still_active:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Share rotation is blocked while a recovery request "
                "is pending or approved."
            ),
        )

    # Lock every asset belonging to the policy.
    assets = db.scalars(
        select(ProtectedAsset)
        .where(ProtectedAsset.policy_id == policy.id)
        .order_by(ProtectedAsset.id)
        .with_for_update()
    ).all()

    if not assets:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This policy has no protected assets to rotate.",
        )

    actual_asset_ids = {asset.id for asset in assets}
    supplied_asset_ids = [
        item.asset_id for item in data.assets
    ]

    if len(supplied_asset_ids) != len(set(supplied_asset_ids)):
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail="Duplicate asset IDs are not allowed.",
        )

    if set(supplied_asset_ids) != actual_asset_ids:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    "Every protected asset under this policy must "
                    "be included exactly once."
                ),
                "missing_asset_ids": sorted(
                    actual_asset_ids - set(supplied_asset_ids)
                ),
                "unexpected_asset_ids": sorted(
                    set(supplied_asset_ids) - actual_asset_ids
                ),
            },
        )

    # All assets must currently be in the same policy epoch.
    wrong_epoch_assets = [
        asset.id
        for asset in assets
        if asset.epoch != previous_epoch
    ]

    if wrong_epoch_assets:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Some assets are not synchronized with "
                    "the current policy epoch."
                ),
                "asset_ids": wrong_epoch_assets,
                "policy_epoch": previous_epoch,
            },
        )

    # Load and lock all assigned trustees.
    trustees = db.scalars(
        select(Trustee)
        .where(Trustee.id.in_(assigned_trustee_ids))
        .order_by(Trustee.id)
        .with_for_update()
    ).all()

    trustees_by_id = {
        trustee.id: trustee
        for trustee in trustees
    }

    if set(trustees_by_id) != assigned_trustee_ids:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="One or more assigned trustees no longer exist.",
        )

    inactive_trustees = [
        trustee.id
        for trustee in trustees
        if not trustee.active
    ]

    if inactive_trustees:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "All assigned trustees must be active "
                    "before share rotation."
                ),
                "inactive_trustee_ids": inactive_trustees,
            },
        )

    trustees_without_keys = [
        trustee.id
        for trustee in trustees
        if not trustee.public_key
    ]

    if trustees_without_keys:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Every assigned trustee must have a registered "
                    "encryption public key."
                ),
                "trustee_ids": trustees_without_keys,
            },
        )

    # Validate every new encrypted share before writing anything.
    pending_shares: list[EncryptedShare] = []

    for asset_input in data.assets:
        asset = next(
            item
            for item in assets
            if item.id == asset_input.asset_id
        )

        supplied_trustee_ids = [
            item.trustee_id
            for item in asset_input.shares
        ]

        if len(supplied_trustee_ids) != len(
            set(supplied_trustee_ids)
        ):
            db.rollback()
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Duplicate trustee shares are not allowed.",
                    "asset_id": asset.id,
                },
            )

        if set(supplied_trustee_ids) != assigned_trustee_ids:
            db.rollback()
            raise HTTPException(
                status_code=422,
                detail={
                    "message": (
                        "Every asset must have exactly one new share "
                        "for each assigned trustee."
                    ),
                    "asset_id": asset.id,
                    "missing_trustees": sorted(
                        assigned_trustee_ids - set(supplied_trustee_ids)
                    ),
                    "unexpected_trustees": sorted(
                        set(supplied_trustee_ids) - assigned_trustee_ids
                    ),
                },
            )

        for share_input in asset_input.shares:
            trustee_id = share_input.trustee_id

            if not validate_commitment_format(
                share_input.commitment
            ):
                db.rollback()
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Invalid share commitment format.",
                        "asset_id": asset.id,
                        "trustee_id": trustee_id,
                    },
                )

            valid, reason = validate_share_envelope(
                share_input.encrypted_share,
                expected_policy_id=policy.id,
                expected_trustee_id=trustee_id,
                expected_epoch=new_epoch,
            )

            if not valid:
                db.rollback()
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Invalid new encrypted share envelope.",
                        "asset_id": asset.id,
                        "trustee_id": trustee_id,
                        "reason": reason,
                    },
                )

            pending_shares.append(
                EncryptedShare(
                    id=generate_identifier(),
                    asset_id=asset.id,
                    trustee_id=trustee_id,
                    encrypted_share=share_input.encrypted_share,
                    commitment=share_input.commitment.lower(),
                    epoch=new_epoch,
                )
            )

    try:
        # The database unique constraint provides an additional
        # safeguard against duplicate asset/trustee/epoch records.
        db.add_all(pending_shares)

        # Move every asset and the policy to the new epoch together.
        for asset in assets:
            asset.epoch = new_epoch

        policy.epoch = new_epoch
        policy.version += 1

        db.commit()

    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Share rotation conflicted with an existing epoch "
                "or another database constraint."
            ),
        ) from exc

    except Exception:
        db.rollback()
        raise

    return ShareRotationResponse(
        policy_id=policy.id,
        previous_epoch=previous_epoch,
        new_epoch=new_epoch,
        new_policy_version=policy.version,
        updated_asset_count=len(assets),
        inserted_share_count=len(pending_shares),
        message=(
            "Share rotation completed. New encrypted shares are "
            "stored and the policy and all protected assets now use "
            "the new epoch. Previous epoch records were retained."
        ),
    )
