
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    auth_router,
    assets_router,
    audit_logs_router,
    health_router,
    policies_router,
    recovery_router,
    recovery_packages_router,
    shares_router,
    trustees_router,
    share_rotation_router,
)
from app.blockchain import BlockchainClient
from app.core.config import settings
from app.db.database import SessionLocal
from app.services.audit_log import record_request_safely


logger = logging.getLogger(__name__)


app = FastAPI(
    title=settings.app_name,
    description=(
        "Publicly Verifiable, Policy-Composable "
        "Emergency Recovery Protocol"
    ),
    version="0.1.0",
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
    Record metadata for every state-changing API request.

    No request body or secret material is stored.
    """

    try:
        response = await call_next(request)
        status_code = response.status_code

    except Exception:
        status_code = 500
        raise

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
                    status_code=locals().get(
                        "status_code",
                        500,
                    ),
                )
            finally:
                db.close()

    return response


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

blockchain = BlockchainClient(
    rpc_url=settings.blockchain_rpc_url,
    chain_id=settings.blockchain_chain_id,
)


@app.get("/")
def root():
    return {
        "service": "DeadDrop",
        "status": "operational",
        "version": "0.1.0",
    }


@app.get("/api/blockchain/status")
def blockchain_status():
    return {
        "configured_chain_id": blockchain.chain_id,
        "connected": blockchain.connected,
        "network_chain_id": blockchain.get_chain_id(),
        "block_number": blockchain.get_block_number(),
    }
