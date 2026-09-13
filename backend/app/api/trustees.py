from __future__ import annotations

from fastapi import APIRouter

from app.core.security import generate_identifier
from app.schemas import TrusteeCreate, TrusteeResponse

router = APIRouter(
    prefix="/api/trustees",
    tags=["Trustees"],
)

trustees: dict[str, TrusteeResponse] = {}


@router.post("", response_model=TrusteeResponse)
def create_trustee(payload: TrusteeCreate):
    trustee_id = generate_identifier()

    trustee = TrusteeResponse(
        id=trustee_id,
        name=payload.name,
        role=payload.role,
        wallet_address=payload.wallet_address,
        public_key=payload.public_key,
        active=True,
    )

    trustees[trustee_id] = trustee

    return trustee


@router.get("", response_model=list[TrusteeResponse])
def list_trustees():
    return list(trustees.values())