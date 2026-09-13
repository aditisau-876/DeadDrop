from fastapi import APIRouter

from app.crypto.commitments import create_share_commitment
from app.schemas import ShareReadinessResponse

router = APIRouter(
    prefix="/api/readiness",
    tags=["Readiness"],
)


@router.get(
    "/{policy_id}/{trustee_id}",
    response_model=ShareReadinessResponse,
)
def get_readiness(
    policy_id: str,
    trustee_id: str,
):
    # Temporary deterministic demonstration value.
    # Real share commitments will come from the cryptographic
    # provisioning workflow.
    demo_share = f"demo-share:{trustee_id}"

    commitment = create_share_commitment(
        demo_share,
        policy_id=policy_id,
        trustee_id=trustee_id,
        epoch=1,
    )

    return ShareReadinessResponse(
        policy_id=policy_id,
        trustee_id=trustee_id,
        epoch=1,
        commitment=commitment,
        verified=True,
    )