
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.policy import Policy
from app.models.recovery import RecoveryApproval, RecoveryRequest
from app.models.trustee import Trustee
from app.schemas.recovery import (
    RecoveryCreate,
    RecoveryApproval as RecoveryApprovalInput,
    RecoveryResponse,
)
from app.services.access_structure import evaluate
from app.crypto.signatures import verify_approval_signature


router = APIRouter(prefix="/api/recovery", tags=["Recovery"])


def serialize_recovery(recovery: RecoveryRequest) -> dict:
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
    }


@router.post(
    "",
    response_model=RecoveryResponse,
    status_code=status.HTTP_201_CREATED,
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
            status_code=409,
            detail="This policy is inactive.",
        )

    if not policy.policy_tree:
        raise HTTPException(
            status_code=409,
            detail="This policy does not have a structured access policy.",
        )

    recovery = RecoveryRequest(
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

    return serialize_recovery(recovery)


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

    return serialize_recovery(recovery)


@router.post(
    "/{recovery_id}/approve",
    response_model=RecoveryResponse,
)
def approve_recovery(
    recovery_id: str,
    data: RecoveryApprovalInput,
    db: Session = Depends(get_db),
):
    if data.recovery_id != recovery_id:
        raise HTTPException(
            status_code=400,
            detail="Recovery ID mismatch.",
        )

    recovery = db.get(RecoveryRequest, recovery_id)

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    if recovery.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail="This recovery request is no longer pending.",
        )

    policy = db.get(Policy, recovery.policy_id)

    if policy is None or not policy.active:
        raise HTTPException(
            status_code=409,
            detail="The associated policy is unavailable or inactive.",
        )

    # Prevent approvals against a policy that has changed since
    # this recovery request was created.
    if (
        policy.version != recovery.policy_version
        or policy.epoch != recovery.policy_epoch
    ):
        raise HTTPException(
            status_code=409,
            detail="The policy changed after this recovery request was created.",
        )

    if not policy.policy_tree:
        raise HTTPException(
            status_code=409,
            detail="This policy has no structured access policy.",
        )

    trustee = db.get(Trustee, data.trustee_id)

    if trustee is None or not trustee.active:
        raise HTTPException(
            status_code=403,
            detail="Trustee does not exist or is inactive.",
        )

    if data.trustee_id not in policy.trustee_ids:
        raise HTTPException(
            status_code=403,
            detail="This trustee is not assigned to the policy.",
        )

    # Verify the actual Ethereum wallet signature.
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

    existing_approval = db.scalar(
        select(RecoveryApproval).where(
            RecoveryApproval.recovery_id == recovery.id,
            RecoveryApproval.trustee_id == trustee.id,
        )
    )

    if existing_approval is not None:
        raise HTTPException(
            status_code=409,
            detail="This trustee has already approved this recovery.",
        )

    approval = RecoveryApproval(
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
                select(RecoveryApproval.trustee_id).where(
                    RecoveryApproval.recovery_id == recovery.id
                )
            ).all()
        )

        recovery.approvals = len(approved_trustees)

        # The structured tree determines whether governance
        # authorization has been satisfied.
        if evaluate(policy.policy_tree, approved_trustees):
            recovery.status = "APPROVED"

        db.commit()
        db.refresh(recovery)

    except Exception:
        db.rollback()
        raise

    return serialize_recovery(recovery)
