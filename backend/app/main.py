
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    auth_router,
    assets_router,
    audit_logs_router,
    blockchain_router,
    health_router,
    policies_router,
    recovery_router,
    recovery_packages_router,
    shares_router,
    trustees_router,
    share_rotation_router,
)
from app.core.config import settings
from app.db.database import SessionLocal
from app.services.audit_log import record_request_safely
from app.api.blockchain_events import (
    router as blockchain_events_router,
)

logger = logging.getLogger(__name__)


app = FastAPI(
    title=settings.app_name,
    description=(
        "Publicly Verifiable, Policy-Composable "
        "Emergency Recovery Protocol"
    ),
    version="0.2.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def audit_mutating_requests(
    request: Request,
    call_next,
):
    """
    Record metadata for state-changing requests.
    Request bodies and secret material are never stored.
    """

    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response

    finally:
        if request.method.upper() in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            db = SessionLocal()

            try:
                record_request_safely(
                    db=db,
                    request=request,
                    status_code=status_code,
                )
            finally:
                db.close()


app.include_router(health_router)
app.include_router(auth_router)
app.include_router(policies_router)
app.include_router(trustees_router)
app.include_router(recovery_router)
app.include_router(recovery_packages_router)
app.include_router(assets_router)
app.include_router(shares_router)
app.include_router(audit_logs_router)
app.include_router(share_rotation_router)
app.include_router(blockchain_router)
app.include_router(blockchain_events_router)

@app.get("/")
def root():
    return {
        "service": "DeadDrop",
        "status": "operational",
        "version": "0.2.0",
    }


