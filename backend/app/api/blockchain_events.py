from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blockchain.indexer import sync_contract_events
from app.core.security import require_roles
from app.db.database import get_db
from app.models.blockchain_event import BlockchainEvent
from app.models.blockchain_projection import (
    BlockchainRecoveryProjection,
)
from app.blockchain.reconciliation import (
    reconcile_blockchain_state,
)
from app.blockchain.rotation_reconciliation import (
    reconcile_rotation_state,
)

router = APIRouter(
    prefix="/api/blockchain/events",
    tags=["Blockchain Events"],
)


@router.post("/sync")
def synchronize_blockchain_events(
    max_blocks: int | None = Query(
        default=None,
        ge=1,
        le=100000,
    ),
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    try:
        return sync_contract_events(
            db=db,
            max_blocks=max_blocks,
        )

    except (ConnectionError, ValueError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Blockchain event synchronization failed.",
        ) from exc


@router.get("")
def list_blockchain_events(
    event_name: str | None = Query(default=None),
    from_block: int | None = Query(default=None, ge=0),
    to_block: int | None = Query(default=None, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    query = select(BlockchainEvent)

    if event_name:
        query = query.where(
            BlockchainEvent.event_name == event_name
        )

    if from_block is not None:
        query = query.where(
            BlockchainEvent.block_number >= from_block
        )

    if to_block is not None:
        query = query.where(
            BlockchainEvent.block_number <= to_block
        )

    if (
        from_block is not None
        and to_block is not None
        and from_block > to_block
    ):
        raise HTTPException(
            status_code=400,
            detail="from_block cannot be greater than to_block.",
        )

    query = (
        query
        .order_by(
            BlockchainEvent.block_number.desc(),
            BlockchainEvent.log_index.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    events = db.scalars(query).all()

    return [
        {
            "id": event.id,
            "chain_id": event.chain_id,
            "contract_address": event.contract_address,
            "block_number": event.block_number,
            "block_hash": event.block_hash,
            "transaction_hash": event.transaction_hash,
            "transaction_index": event.transaction_index,
            "log_index": event.log_index,
            "event_name": event.event_name,
            "event_args": event.event_args,
            "block_timestamp": (
                event.block_timestamp.isoformat()
                if event.block_timestamp
                else None
            ),
            "indexed_at": event.indexed_at.isoformat(),
        }
        for event in events
    ]

@router.get("/recoveries")
def list_blockchain_recovery_projections(
    state: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    query = select(BlockchainRecoveryProjection)

    if state:
        query = query.where(
            BlockchainRecoveryProjection.state == state.upper()
        )

    query = (
        query
        .order_by(
            BlockchainRecoveryProjection.last_event_block.desc()
        )
        .offset(offset)
        .limit(limit)
    )

    projections = db.scalars(query).all()

    return [
        {
            "id": item.id,
            "chain_id": item.chain_id,
            "contract_address": item.contract_address,
            "recovery_key": item.recovery_key,
            "recovery_id": item.recovery_id,
            "policy_key": item.policy_key,
            "requester": item.requester,
            "state": item.state,
            "approvals": item.approvals,
            "execute_after": (
                item.execute_after.isoformat()
                if item.execute_after else None
            ),
            "expires_at": (
                item.expires_at.isoformat()
                if item.expires_at else None
            ),
            "requested_at": (
                item.requested_at.isoformat()
                if item.requested_at else None
            ),
            "completed_at": (
                item.completed_at.isoformat()
                if item.completed_at else None
            ),
            "cancelled_at": (
                item.cancelled_at.isoformat()
                if item.cancelled_at else None
            ),
            "artifact_hash": item.artifact_hash,
            "last_event_block": item.last_event_block,
            "last_event_transaction": item.last_event_transaction,
            "updated_at": item.updated_at.isoformat(),
        }
        for item in projections
    ]

@router.get("/reconcile")
def reconcile_blockchain(
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    try:
        return reconcile_blockchain_state(db)

    except (ConnectionError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Blockchain reconciliation failed.",
        ) from exc

@router.get("/reconcile/rotations")
def reconcile_blockchain_rotations(
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    """
    Compare database policy and asset epochs with confirmed
    on-chain state. This endpoint is read-only.
    """
    try:
        return reconcile_rotation_state(db)

    except (ConnectionError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Blockchain rotation reconciliation failed.",
        ) from exc