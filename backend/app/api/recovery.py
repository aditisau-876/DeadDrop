from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_identifier
from app.db.database import get_db
from app.models.policy import Policy
from app.models.recovery import RecoveryApproval, RecoveryRequest
from app.models.trustee import Trustee
from app.schemas.recovery import (
    RecoveryApproval as RecoveryApprovalSchema,
    RecoveryCreate,
    RecoveryResponse,
)


router = APIRouter(
    prefix="/api/recovery",
    tags=["Recovery"],
)


@router.post(
    "",
    response_model=RecoveryResponse,
    status_code=201,
)
def create_recovery(
    data: RecoveryCreate,
    db: Session = Depends(get_db),
):
    policy = db.get(Policy, data.policy_id)

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    if not policy.active:
        raise HTTPException(
            status_code=400,
            detail="Policy is inactive.",
        )

    recovery = RecoveryRequest(
    id=generate_identifier(),
    policy_id=policy.id,
    reason=data.reason,
    incident_hash=data.incident_hash,
    status="PENDING",
    approvals=0,
    required_approvals=3,
    policy_version=policy.version,
    policy_epoch=policy.epoch,
)

    db.add(recovery)
    db.commit()
    db.refresh(recovery)

    return recovery


@router.get(
    "/{recovery_id}",
    response_model=RecoveryResponse,
)
def get_recovery(
    recovery_id: str,
    db: Session = Depends(get_db),
):
    recovery = db.get(RecoveryRequest, recovery_id)

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    return recovery


@router.post(
    "/{recovery_id}/approve",
    response_model=RecoveryResponse,
)
def approve_recovery(
    recovery_id: str,
    data: RecoveryApprovalSchema,
    db: Session = Depends(get_db),
):
    recovery = db.get(RecoveryRequest, recovery_id)

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    if recovery.status != "PENDING":
        raise HTTPException(
            status_code=400,
            detail="Recovery request is no longer pending.",
        )

    if data.recovery_id != recovery_id:
        raise HTTPException(
            status_code=400,
            detail="Recovery ID mismatch.",
        )

    trustee = db.get(Trustee, data.trustee_id)

    if trustee is None:
        raise HTTPException(
            status_code=404,
            detail="Trustee not found.",
        )

    if not trustee.active:
        raise HTTPException(
            status_code=400,
            detail="Trustee is inactive.",
        )

    policy = db.get(Policy, recovery.policy_id)

    if policy is None:
        raise HTTPException(
            status_code=500,
            detail="Recovery policy could not be found.",
        )

    if data.trustee_id not in policy.trustee_ids:
        raise HTTPException(
            status_code=403,
            detail="Trustee is not assigned to this policy.",
        )

    # Prevent duplicate trustee approvals.
    existing = db.scalar(
        select(RecoveryApproval).where(
            RecoveryApproval.recovery_id == recovery_id,
            RecoveryApproval.trustee_id == data.trustee_id,
        )
    )

    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="Trustee has already approved this recovery request.",
        )

    approval = RecoveryApproval(
        id=generate_identifier(),
        recovery_id=recovery_id,
        trustee_id=data.trustee_id,
        signature=data.signature,
    )

    db.add(approval)

    recovery.approvals += 1

    if recovery.approvals >= recovery.required_approvals:
        recovery.status = "APPROVED"

    db.commit()
    db.refresh(recovery)

    return recovery