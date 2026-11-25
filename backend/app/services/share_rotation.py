
from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from web3 import Web3

from app.core.security import generate_identifier
from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.models.recovery import RecoveryRequest
from app.models.share import EncryptedShare
from app.models.trustee import Trustee
from app.models.share_rotation_attempt import ShareRotationAttempt
from app.schemas.share_rotation import ShareRotationRequest
from app.services.recovery_lifecycle import expire_recovery_if_needed
from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)


def validate_rotation_request(
    db: Session,
    policy_id: str,
    data: ShareRotationRequest,
):
    """Validate a complete rotation without writing to the database."""

    policy = db.scalar(
        select(Policy)
        .where(Policy.id == policy_id)
        .with_for_update()
    )

    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found.")

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

    previous_epoch = int(policy.epoch)
    new_epoch = previous_epoch + 1

    trustee_ids = list(policy.trustee_ids or [])
    trustee_id_set = set(trustee_ids)

    if len(trustee_id_set) != len(trustee_ids):
        raise HTTPException(
            status_code=409,
            detail="The policy contains duplicate trustee assignments.",
        )

    if len(trustee_id_set) < 2:
        raise HTTPException(
            status_code=409,
            detail="The policy needs at least two assigned trustees.",
        )

    recoveries = db.scalars(
        select(RecoveryRequest)
        .where(
            RecoveryRequest.policy_id == policy.id,
            RecoveryRequest.status.in_(["PENDING", "APPROVED"]),
        )
        .with_for_update()
    ).all()

    now = datetime.utcnow()

    for recovery in recoveries:
        expire_recovery_if_needed(recovery, now)

    if any(
        item.status in {"PENDING", "APPROVED"}
        for item in recoveries
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "Share rotation is blocked while a recovery "
                "request is pending or approved."
            ),
        )

    assets = db.scalars(
        select(ProtectedAsset)
        .where(ProtectedAsset.policy_id == policy.id)
        .order_by(ProtectedAsset.id)
        .with_for_update()
    ).all()

    if not assets:
        raise HTTPException(
            status_code=409,
            detail="This policy has no protected assets to rotate.",
        )

    actual_asset_ids = {item.id for item in assets}
    supplied_asset_ids = [item.asset_id for item in data.assets]

    if len(supplied_asset_ids) != len(set(supplied_asset_ids)):
        raise HTTPException(
            status_code=422,
            detail="Duplicate asset IDs are not allowed.",
        )

    if set(supplied_asset_ids) != actual_asset_ids:
        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    "Every protected asset under this policy "
                    "must be included exactly once."
                ),
                "missing_asset_ids": sorted(
                    actual_asset_ids - set(supplied_asset_ids)
                ),
                "unexpected_asset_ids": sorted(
                    set(supplied_asset_ids) - actual_asset_ids
                ),
            },
        )

    stale_assets = [
        item.id for item in assets
        if item.epoch != previous_epoch
    ]

    if stale_assets:
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Some assets are not synchronized with "
                    "the current policy epoch."
                ),
                "asset_ids": stale_assets,
                "policy_epoch": previous_epoch,
            },
        )

    trustees = db.scalars(
        select(Trustee)
        .where(Trustee.id.in_(trustee_id_set))
        .order_by(Trustee.id)
        .with_for_update()
    ).all()

    by_id = {item.id: item for item in trustees}

    if set(by_id) != trustee_id_set:
        raise HTTPException(
            status_code=409,
            detail="One or more assigned trustees no longer exist.",
        )

    inactive = [item.id for item in trustees if not item.active]

    if inactive:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "All assigned trustees must be active.",
                "inactive_trustee_ids": inactive,
            },
        )

    missing_keys = [item.id for item in trustees if not item.public_key]

    if missing_keys:
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Every assigned trustee must have an "
                    "encryption public key."
                ),
                "trustee_ids": missing_keys,
            },
        )

    missing_wallets = [
        item.id
        for item in trustees
        if not item.wallet_address
        or not Web3.is_address(item.wallet_address)
    ]

    if missing_wallets:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Every assigned trustee must have a valid wallet address.",
                "trustee_ids": missing_wallets,
            },
        )

    ordered_trustees = [by_id[item] for item in trustee_ids]

    wallets = [
        Web3.to_checksum_address(item.wallet_address)
        for item in ordered_trustees
    ]

    if len(set(wallets)) != len(wallets):
        raise HTTPException(
            status_code=422,
            detail="Two or more trustees use the same wallet address.",
        )

    asset_by_id = {item.id: item for item in assets}
    input_by_id = {item.asset_id: item for item in data.assets}

    pending_shares: list[EncryptedShare] = []
    commitment_matrix: list[list[str]] = []

    for asset_id in sorted(actual_asset_ids):
        asset_input = input_by_id[asset_id]

        supplied_ids = [
            item.trustee_id for item in asset_input.shares
        ]

        if (
            len(supplied_ids) != len(set(supplied_ids))
            or set(supplied_ids) != trustee_id_set
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "message": (
                        "Every asset must have exactly one new share "
                        "for each assigned trustee."
                    ),
                    "asset_id": asset_id,
                    "missing_trustees": sorted(
                        trustee_id_set - set(supplied_ids)
                    ),
                    "unexpected_trustees": sorted(
                        set(supplied_ids) - trustee_id_set
                    ),
                },
            )

        shares_by_trustee = {
            item.trustee_id: item
            for item in asset_input.shares
        }

        row: list[str] = []

        for trustee_id in trustee_ids:
            share_input = shares_by_trustee[trustee_id]

            if not validate_commitment_format(
                share_input.commitment
            ):
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Invalid share commitment format.",
                        "asset_id": asset_id,
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
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Invalid new encrypted share envelope.",
                        "asset_id": asset_id,
                        "trustee_id": trustee_id,
                        "reason": reason,
                    },
                )

            row.append("0x" + share_input.commitment.lower())

            pending_shares.append(
                EncryptedShare(
                    id=generate_identifier(),
                    asset_id=asset_id,
                    trustee_id=trustee_id,
                    encrypted_share=share_input.encrypted_share,
                    commitment=share_input.commitment.lower(),
                    epoch=new_epoch,
                )
            )

        commitment_matrix.append(row)

    return {
        "policy": policy,
        "assets": assets,
        "trustees": ordered_trustees,
        "trustee_wallets": wallets,
        "previous_epoch": previous_epoch,
        "new_epoch": new_epoch,
        "pending_shares": pending_shares,
        "asset_ids": sorted(actual_asset_ids),
        "commitment_matrix": commitment_matrix,
    }


def persist_rotation(
    db: Session,
    context: dict,
    attempt: ShareRotationAttempt | None = None,
    transaction_hash: str | None = None,
) -> dict:
    """
    Persist the database projection and mark its attempt finalized
    in the same database transaction.
    """

    policy = context["policy"]
    assets = context["assets"]
    pending = context["pending_shares"]
    new_epoch = context["new_epoch"]

    try:
        db.add_all(pending)

        for asset in assets:
            asset.epoch = new_epoch

        policy.epoch = new_epoch
        policy.version += 1

        result = {
            "policy_id": policy.id,
            "previous_epoch": context["previous_epoch"],
            "new_epoch": new_epoch,
            "new_policy_version": policy.version,
            "updated_asset_count": len(assets),
            "inserted_share_count": len(pending),
            "message": (
                "On-chain rotation verified. New encrypted shares "
                "are stored and the policy and all assets now use "
                "the new epoch. Previous epoch records were retained."
            ),
        }

        if attempt is not None:
            attempt.status = "FINALIZED"
            attempt.transaction_hash = transaction_hash
            attempt.result = result
            db.add(attempt)

        db.commit()
        db.refresh(policy)

        return result

    except Exception:
        db.rollback()
        raise
