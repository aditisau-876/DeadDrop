from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.core.security import generate_identifier
from app.schemas import PolicyCreate, PolicyResponse

router = APIRouter(
    prefix="/api/policies",
    tags=["Policies"],
)

policies: dict[str, PolicyResponse] = {}


@router.post("", response_model=PolicyResponse)
def create_policy(payload: PolicyCreate):
    policy_id = generate_identifier()

    policy = PolicyResponse(
        id=policy_id,
        name=payload.name,
        description=payload.description,
        policy_expression=payload.policy_expression,
        trustee_ids=payload.trustee_ids,
        version=1,
        epoch=1,
        active=True,
    )

    policies[policy_id] = policy

    return policy


@router.get("/{policy_id}", response_model=PolicyResponse)
def get_policy(policy_id: str):
    policy = policies.get(policy_id)

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    return policy