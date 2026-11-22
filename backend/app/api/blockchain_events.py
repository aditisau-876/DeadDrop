from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blockchain.indexer import sync_contract_events
from app.core.security import require_roles
from app.db.database import get_db
from app.models.blockchain_event import BlockchainEvent


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