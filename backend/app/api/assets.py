
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_identifier, get_current_user, require_roles, ensure_owner_or_admin
from app.db.database import get_db
from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.models.share import EncryptedShare
from app.models.trustee import Trustee
from app.schemas.asset import (
    AssetCreate,
    AssetProtectionCreate,
    AssetResponse,
)
from app.services.recovery_readiness import (
    calculate_recovery_readiness,
)
from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)


router = APIRouter(
    prefix="/api/assets",
    dependencies=[Depends(get_current_user)],
    tags=["Protected Assets"],
)


def serialize_asset(asset: ProtectedAsset) -> AssetResponse:
    return AssetResponse(
        id=asset.id,
        policy_id=asset.policy_id,
        name=asset.name,
        description=asset.description,
        epoch=asset.epoch,
        threshold=asset.threshold,
        created_at=asset.created_at.isoformat(),
    )


@router.post(
    "/protect",
    response_model=AssetResponse,
    status_code=201,
)
def protect_asset(
    data: AssetProtectionCreate,
    db: Session = Depends(get_db),
    user = Depends(require_roles("owner", "admin")),
):
    """
    Store an encrypted asset and its trustee-encrypted
    recovery shares atomically.

    The backend never receives the plaintext asset or AES key.
    """

    policy = db.get(Policy, data.policy_id)

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(user, policy.owner_user_id)

    if not policy.active:
        raise HTTPException(
            status_code=400,
            detail="Policy is inactive.",
        )

    expected_trustees = set(policy.trustee_ids or [])

    if not expected_trustees:
        raise HTTPException(
            status_code=400,
            detail="The policy has no assigned trustees.",
        )

    # Cryptographic threshold validation.
    if data.threshold > len(expected_trustees):
        raise HTTPException(
            status_code=422,
            detail=(
                "The cryptographic threshold cannot exceed "
                "the number of assigned trustees."
            ),
        )

    supplied_trustees = [
        share.trustee_id
        for share in data.shares
    ]

    # Reject duplicate trustee shares.
    if len(supplied_trustees) != len(set(supplied_trustees)):
        raise HTTPException(
            status_code=400,
            detail="Duplicate trustee shares are not allowed.",
        )

    # Require exactly one share per assigned trustee.
    if set(supplied_trustees) != expected_trustees:
        raise HTTPException(
            status_code=400,
            detail={
                "message": (
                    "Exactly one share must be supplied "
                    "for every trustee assigned to the policy."
                ),
                "missing_trustees": sorted(
                    expected_trustees - set(supplied_trustees)
                ),
                "unexpected_trustees": sorted(
                    set(supplied_trustees) - expected_trustees
                ),
            },
        )

    # Verify that all assigned trustees exist.
    trustees = db.scalars(
        select(Trustee).where(
            Trustee.id.in_(expected_trustees)
        )
    ).all()

    if len(trustees) != len(expected_trustees):
        raise HTTPException(
            status_code=400,
            detail="One or more policy trustees no longer exist.",
        )

    # Reject inactive trustees.
    inactive_ids = [
        trustee.id
        for trustee in trustees
        if not trustee.active
    ]

    if inactive_ids:
        raise HTTPException(
            status_code=400,
            detail={
                "message": (
                    "Inactive trustees cannot receive new shares."
                ),
                "inactive_trustee_ids": inactive_ids,
            },
        )

    # All supplied shares must belong to the current policy epoch.
    # Validate the commitment format and encrypted envelope metadata.
    # These checks do not prove that the underlying Shamir shares
    # are mathematically valid.
    for share_data in data.shares:
        if not validate_commitment_format(share_data.commitment):
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Invalid share commitment format.",
                    "trustee_id": share_data.trustee_id,
                },
            )

        valid, reason = validate_share_envelope(
            share_data.encrypted_share,
            expected_policy_id=policy.id,
            expected_trustee_id=share_data.trustee_id,
            expected_epoch=policy.epoch,
        )

        if not valid:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Invalid encrypted share envelope.",
                    "trustee_id": share_data.trustee_id,
                    "reason": reason,
                },
            )

    wrong_epochs = [
        share.trustee_id
        for share in data.shares
        if share.epoch != policy.epoch
    ]

    if wrong_epochs:
        raise HTTPException(
            status_code=400,
            detail={
                "message": (
                    "All shares must use the current policy epoch."
                ),
                "expected_epoch": policy.epoch,
                "trustees_with_wrong_epoch": wrong_epochs,
            },
        )

    # Create the protected asset.
    asset = ProtectedAsset(
        id=generate_identifier(),
        owner_user_id=policy.owner_user_id,
        policy_id=policy.id,
        name=data.name,
        description=data.description,
        ciphertext=data.ciphertext,
        nonce=data.nonce,
        aad=data.aad,
        epoch=policy.epoch,
        threshold=data.threshold,
    )

    try:
        db.add(asset)
        db.flush()

        # Store all encrypted shares.
        for share_data in data.shares:
            share = EncryptedShare(
                id=generate_identifier(),
                asset_id=asset.id,
                trustee_id=share_data.trustee_id,
                encrypted_share=share_data.encrypted_share,
                commitment=share_data.commitment.lower(),
                epoch=share_data.epoch,
            )

            db.add(share)

        db.commit()
        db.refresh(asset)

    except Exception:
        db.rollback()
        raise

    return serialize_asset(asset)


@router.post(
    "",
    response_model=AssetResponse,
    status_code=201,
)
def create_asset(
    data: AssetCreate,
    db: Session = Depends(get_db),
    user = Depends(require_roles("owner", "admin")),
):
    """
    Legacy encrypted-asset creation endpoint.

    For a complete protected asset with trustee shares,
    use POST /api/assets/protect.
    """

    policy = db.get(Policy, data.policy_id)
    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(user, policy.owner_user_id)

    if not policy.active:
        raise HTTPException(
            status_code=400,
            detail="Policy is inactive.",
        )

    if data.epoch != policy.epoch:
        raise HTTPException(
            status_code=400,
            detail="Asset epoch does not match policy epoch.",
        )

    asset = ProtectedAsset(
        id=generate_identifier(),
        owner_user_id=policy.owner_user_id,
        policy_id=policy.id,
        name=data.name,
        description=data.description,
        ciphertext=data.ciphertext,
        nonce=data.nonce,
        aad=data.aad,
        epoch=data.epoch,
        threshold=3,
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return serialize_asset(asset)


@router.get(
    "",
    response_model=list[AssetResponse],
)
def list_assets(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    query = select(ProtectedAsset).order_by(ProtectedAsset.created_at)
    if user.role != "admin": query = query.where(ProtectedAsset.owner_user_id == user.id)
    assets = db.scalars(query).all()

    return [
        serialize_asset(asset)
        for asset in assets
    ]


@router.get(
    "/{asset_id}/readiness",
)
def get_asset_readiness(
    asset_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """
    Calculate structural recovery readiness.

    This does not prove that the underlying Shamir shares
    are mathematically valid.
    """

    asset = db.get(
        ProtectedAsset,
        asset_id,
    )

    if asset is None:
        raise HTTPException(status_code=404, detail="Protected asset not found.")
    ensure_owner_or_admin(user, asset.owner_user_id)

    return calculate_recovery_readiness(
        db,
        asset,
    )


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    asset = db.get(
        ProtectedAsset,
        asset_id,
    )

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Protected asset not found.",
        )

    ensure_owner_or_admin(user, asset.owner_user_id)
    return serialize_asset(asset)
