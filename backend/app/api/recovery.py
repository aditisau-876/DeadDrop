from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.core.security import generate_identifier
from app.schemas import (
    RecoveryApproval,
    RecoveryCreate,
    RecoveryResponse,
)

router = APIRouter(
    prefix="/api/recovery",
    tags=["Recovery"],
)

recoveries: dict[str, RecoveryResponse] = {}


@router.post("", response_model=RecoveryResponse)
def create_recovery(payload: RecoveryCreate):
    recovery_id = generate_identifier()

    recovery = RecoveryResponse(
        id=recovery_id,
        policy_id=payload.policy_id,
        reason=payload.reason,
        incident_hash=payload.incident_hash,
        status="PENDING",
        approvals=0,
        required_approvals=3,
    )

    recoveries[recovery_id] = recovery

    return recovery


@router.get(
    "/{recovery_id}",
    response_model=RecoveryResponse,
)
def get_recovery(recovery_id: str):
    recovery = recoveries.get(recovery_id)

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
    payload: RecoveryApproval,
):
    recovery = recoveries.get(recovery_id)

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    if recovery.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail="Recovery request is no longer pending.",
        )

    recovery.approvals += 1

    if recovery.approvals >= recovery.required_approvals:
        recovery.status = "APPROVED"

    return recovery