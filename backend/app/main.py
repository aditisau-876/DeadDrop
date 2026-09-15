from fastapi import FastAPI

from app.api import (
    health_router,
    policies_router,
    trustees_router,
    recovery_router,
    readiness_router,
)
from app.blockchain import BlockchainClient
from app.core.config import settings


app = FastAPI(
    title=settings.app_name,
    description=(
        "Publicly Verifiable, Policy-Composable "
        "Emergency Recovery Protocol"
    ),
    version="0.1.0",
)


app.include_router(health_router)
app.include_router(policies_router)
app.include_router(trustees_router)
app.include_router(recovery_router)
app.include_router(readiness_router)


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