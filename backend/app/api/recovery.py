
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    generate_identifier,
    get_current_user,
    require_roles,
    ensure_owner_or_admin,
)
from app.db.database import get_db

from app.models.policy import Policy
from app.models.recovery import (
    RecoveryApproval as RecoveryApprovalModel,
    RecoveryRequest,
)
from app.models.trustee import Trustee

from app.schemas.recovery import (
    RecoveryCreate,
    RecoveryApproval as RecoveryApprovalInput,
    RecoveryCancel,
    RecoveryResponse,
)

from app.services.access_structure import (
    evaluate,
    minimum_approvals,
)

from app.services.recovery_lifecycle import (
    expire_recovery_if_needed,
    recovery_release_block_reason,
)

from app.crypto.signatures import verify_approval_signature


router = APIRouter(
    prefix="/api/recovery",
    tags=["Recovery"],
)


def serialize_recovery(
    recovery: RecoveryRequest,
) -> dict:
    now = datetime.utcnow()

    can_release = (
        recovery.status == "APPROVED"
        and recovery.execute_after is not None
        and recovery.execute_after <= now
        and (
            recovery.expires_at is None
            or recovery.expires_at > now
        )
    )

    return {
        "id": recovery.id,
        "policy_id": recovery.policy_id,
        "reason": recovery.reason,
        "incident_hash": recovery.incident_hash,
        "status": recovery.status,
        "approvals": recovery.approvals,
        "required_approvals": recovery.required_approvals,
        "policy_version": recovery.policy_version,
        "policy_epoch": recovery.policy_epoch,
        "expires_at": (
            recovery.expires_at.isoformat()
            if recovery.expires_at
            else None
        ),
        "execute_after": (
            recovery.execute_after.isoformat()
            if recovery.execute_after
            else None
        ),
        "cancelled_at": (
            recovery.cancelled_at.isoformat()
            if recovery.cancelled_at
            else None
        ),
        "cancellation_reason": recovery.cancellation_reason,
        "completed_at": (
            recovery.completed_at.isoformat()
            if recovery.completed_at
            else None
        ),
        "can_release": can_release,
    }


def can_view_recovery(
    user,
    policy: Policy,
    db: Session,
) -> bool:
    if user.role == "admin":
        return True

    if user.role == "owner":
        return policy.owner_user_id == user.id

    if user.role == "trustee":
        trustee = db.scalar(
            select(Trustee).where(
                Trustee.user_id == user.id
            )
        )

        if trustee is None or not trustee.active:
            return False

        return trustee.id in set(policy.trustee_ids or [])

    return False


def refresh_expiry(
    recovery: RecoveryRequest,
    db: Session,
) -> None:
    changed = expire_recovery_if_needed(recovery)

    if changed:
        db.commit()
        db.refresh(recovery)


@router.post(
    "",
    response_model=RecoveryResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_recovery(
    data: RecoveryCreate,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    policy = db.scalar(select(Policy).where(Policy.id == data.policy_id).with_for_update())

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(
        user,
        policy.owner_user_id,
    )

    if not policy.active:
        raise HTTPException(
            status_code=409,
            detail="This policy is inactive.",
        )

    if (
        policy.expiry_seconds is not None
        and policy.expiry_seconds <= (policy.timelock_seconds or 0)
    ):
        raise HTTPException(
            status_code=422,
            detail="Policy expiry must be longer than its recovery timelock.",
        )

    if not policy.policy_tree:
        raise HTTPException(
            status_code=409,
            detail=(
                "This policy does not have "
                "a structured access policy."
            ),
        )

    try:
        required = minimum_approvals(
            policy.policy_tree
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid policy tree: {exc}",
        ) from exc

    now = datetime.utcnow()

    expires_at = None

    if policy.expiry_seconds is not None:
        expires_at = now + timedelta(
            seconds=policy.expiry_seconds
        )

    recovery = RecoveryRequest(
        id=generate_identifier(),
        policy_id=policy.id,
        reason=data.reason,
        incident_hash=data.incident_hash,
        status="PENDING",
        approvals=0,
        required_approvals=required,
        policy_version=policy.version,
        policy_epoch=policy.epoch,
        expires_at=expires_at,
        execute_after=None,
        created_at=now,
    )

    db.add(recovery)
    db.commit()
    db.refresh(recovery)

    return serialize_recovery(recovery)


@router.get(
    "",
    response_model=list[RecoveryResponse],
)
def list_recoveries(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recoveries = db.scalars(
        select(RecoveryRequest).order_by(
            RecoveryRequest.created_at.desc()
        )
    ).all()

    visible = []

    for recovery in recoveries:
        policy = db.get(
            Policy,
            recovery.policy_id,
        )

        if policy is None:
            continue

        if not can_view_recovery(
            user,
            policy,
            db,
        ):
            continue

        if expire_recovery_if_needed(recovery):
            db.flush()

        visible.append(recovery)

    db.commit()

    return [
        serialize_recovery(recovery)
        for recovery in visible
    ]


@router.get(
    "/{recovery_id}",
    response_model=RecoveryResponse,
)
def get_recovery(
    recovery_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recovery = db.get(
        RecoveryRequest,
        recovery_id,
    )

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    policy = db.get(
        Policy,
        recovery.policy_id,
    )

    if policy is None or not can_view_recovery(
        user,
        policy,
        db,
    ):
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    refresh_expiry(
        recovery,
        db,
    )

    return serialize_recovery(recovery)


@router.post(
    "/{recovery_id}/approve",
    response_model=RecoveryResponse,
)
def approve_recovery(
    recovery_id: str,
    data: RecoveryApprovalInput,
    db: Session = Depends(get_db),
    user=Depends(require_roles("trustee", "admin")),
):
    if data.recovery_id != recovery_id:
        raise HTTPException(
            status_code=400,
            detail="Recovery ID mismatch.",
        )

    # Lock the recovery row while processing an approval.
    recovery = db.scalar(
        select(RecoveryRequest)
        .where(
            RecoveryRequest.id == recovery_id
        )
        .with_for_update()
    )

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    if expire_recovery_if_needed(recovery):
        db.commit()

        raise HTTPException(
            status_code=410,
            detail="This recovery request has expired.",
        )

    if recovery.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail="This recovery request is no longer pending.",
        )

    policy = db.get(
        Policy,
        recovery.policy_id,
    )

    if policy is None or not policy.active:
        raise HTTPException(
            status_code=409,
            detail=(
                "The associated policy is unavailable "
                "or inactive."
            ),
        )

    if (
        policy.version != recovery.policy_version
        or policy.epoch != recovery.policy_epoch
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "The policy changed after this recovery "
                "request was created."
            ),
        )

    if not policy.policy_tree:
        raise HTTPException(
            status_code=409,
            detail="This policy has no structured access policy.",
        )

    trustee = db.get(
        Trustee,
        data.trustee_id,
    )

    if trustee is None or not trustee.active:
        raise HTTPException(
            status_code=403,
            detail="Trustee does not exist or is inactive.",
        )

    if (
        user.role == "trustee"
        and trustee.user_id != user.id
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "This account is not linked "
                "to the requested trustee."
            ),
        )

    if trustee.id not in set(policy.trustee_ids or []):
        raise HTTPException(
            status_code=403,
            detail="This trustee is not assigned to the policy.",
        )

    signature_valid = verify_approval_signature(
        signature=data.signature,
        expected_wallet=trustee.wallet_address or "",
        recovery_id=recovery.id,
        policy_id=policy.id,
        trustee_id=trustee.id,
        incident_hash=recovery.incident_hash,
        policy_version=recovery.policy_version,
        policy_epoch=recovery.policy_epoch,
    )

    if not signature_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid trustee approval signature.",
        )

    existing = db.scalar(
        select(RecoveryApprovalModel).where(
            RecoveryApprovalModel.recovery_id == recovery.id,
            RecoveryApprovalModel.trustee_id == trustee.id,
        )
    )

    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="This trustee has already approved this recovery.",
        )

    approval = RecoveryApprovalModel(
        id=generate_identifier(),
        recovery_id=recovery.id,
        trustee_id=trustee.id,
        signature=data.signature,
        created_at=datetime.utcnow(),
    )

    try:
        db.add(approval)
        db.flush()

        approved_trustees = set(
            db.scalars(
                select(
                    RecoveryApprovalModel.trustee_id
                ).where(
                    RecoveryApprovalModel.recovery_id == recovery.id
                )
            ).all()
        )

        recovery.approvals = len(
            approved_trustees
        )

        if evaluate(
            policy.policy_tree,
            approved_trustees,
        ):
            now = datetime.utcnow()

            timelock_seconds = (
                policy.timelock_seconds or 0
            )

            recovery.status = "APPROVED"

            recovery.execute_after = now + timedelta(
                seconds=timelock_seconds
            )

        db.commit()
        db.refresh(recovery)

    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail=(
                "This trustee has already approved "
                "this recovery."
            ),
        ) from exc

    except Exception:
        db.rollback()
        raise

    return serialize_recovery(recovery)


@router.post(
    "/{recovery_id}/cancel",
    response_model=RecoveryResponse,
)
def cancel_recovery(
    recovery_id: str,
    data: RecoveryCancel,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    recovery = db.scalar(
        select(RecoveryRequest)
        .where(
            RecoveryRequest.id == recovery_id
        )
        .with_for_update()
    )

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    policy = db.get(
        Policy,
        recovery.policy_id,
    )

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Associated policy not found.",
        )

    ensure_owner_or_admin(
        user,
        policy.owner_user_id,
    )

    if expire_recovery_if_needed(recovery):
        db.commit()

        raise HTTPException(
            status_code=410,
            detail="This recovery request has expired.",
        )

    if recovery.status not in {
        "PENDING",
        "APPROVED",
    }:
        raise HTTPException(
            status_code=409,
            detail=(
                "Only pending or approved recovery "
                "requests can be cancelled."
            ),
        )

    recovery.status = "CANCELLED"
    recovery.cancelled_at = datetime.utcnow()
    recovery.cancellation_reason = data.reason

    db.commit()
    db.refresh(recovery)

    return serialize_recovery(recovery)
