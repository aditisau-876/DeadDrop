
from fastapi import APIRouter, HTTPException, status

router = APIRouter(
    prefix="/api/readiness",
    tags=["Readiness"],
)


@router.get("/{policy_id}/{trustee_id}")
def deprecated_readiness_endpoint(
    policy_id: str,
    trustee_id: str,
):
    """
    Retired endpoint.

    Readiness is asset-specific. A policy/trustee pair alone
    cannot establish that a usable encrypted share exists.
    """

    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "message": (
                "This readiness endpoint has been retired. "
                "Use GET /api/assets/{asset_id}/readiness instead."
            ),
            "policy_id": policy_id,
            "trustee_id": trustee_id,
        },
    )
