
from __future__ import annotations

import os
import uuid

from datetime import datetime
from typing import Any
from sqlalchemy import delete, select,text
from sqlalchemy.orm import Session
from web3 import Web3

from app.core.config import settings
from app.models.blockchain_event import (
    BlockchainEvent,
    BlockchainSyncCheckpoint,
)
from app.models.blockchain_projection import (
    BlockchainRecoveryProjection,
)
from app.models.recovery import RecoveryRequest


EVENT_ABI = [
    {
        "anonymous": False,
        "type": "event",
        "name": "PolicyRegistered",
        "inputs": [
            {"indexed": True, "name": "policyKey", "type": "bytes32"},
            {"indexed": False, "name": "policyHash", "type": "bytes32"},
            {"indexed": False, "name": "version", "type": "uint64"},
            {"indexed": False, "name": "epoch", "type": "uint64"},
        ],
    },
    {
        "anonymous": False,
        "type": "event",
        "name": "PolicyStatusChanged",
        "inputs": [
            {"indexed": True, "name": "policyKey", "type": "bytes32"},
            {"indexed": False, "name": "active", "type": "bool"},
        ],
    },
    {
        "anonymous": False,
        "type": "event",
        "name": "ShareCommitmentsUpdated",
        "inputs": [
            {"indexed": True, "name": "policyKey", "type": "bytes32"},
            {"indexed": False, "name": "epoch", "type": "uint64"},
        ],
    },
    {
        "anonymous": False,
        "type": "event",
        "name": "AssetCommitmentsRegistered",
        "inputs": [
            {"indexed": True, "name": "assetKey", "type": "bytes32"},
            {"indexed": True, "name": "policyKey", "type": "bytes32"},
            {"indexed": False, "name": "assetHash", "type": "bytes32"},
            {"indexed": False, "name": "epoch", "type": "uint64"},
        ],
    },
    {
        "anonymous": False,
        "type": "event",
        "name": "RecoveryRequested",
        "inputs": [
            {"indexed": True, "name": "recoveryKey", "type": "bytes32"},
            {"indexed": True, "name": "policyKey", "type": "bytes32"},
            {"indexed": True, "name": "requester", "type": "address"},
            {"indexed": False, "name": "executeAfter", "type": "uint64"},
            {"indexed": False, "name": "expiresAt", "type": "uint64"},
        ],
    },
    {
        "anonymous": False,
        "type": "event",
        "name": "ApprovalSubmitted",
        "inputs": [
            {"indexed": True, "name": "recoveryKey", "type": "bytes32"},
            {"indexed": True, "name": "trustee", "type": "address"},
            {"indexed": False, "name": "approvals", "type": "uint16"},
        ],
    },
    {
        "anonymous": False,
        "type": "event",
        "name": "RecoveryExecuted",
        "inputs": [
            {"indexed": True, "name": "recoveryKey", "type": "bytes32"},
            {"indexed": False, "name": "artifactHash", "type": "bytes32"},
        ],
    },
    {
        "anonymous": False,
        "type": "event",
        "name": "RecoveryCancelled",
        "inputs": [
            {"indexed": True, "name": "recoveryKey", "type": "bytes32"},
            {"indexed": True, "name": "cancelledBy", "type": "address"},
        ],
    },
]


RECOVERY_EVENTS = {
    "RecoveryRequested",
    "ApprovalSubmitted",
    "RecoveryExecuted",
    "RecoveryCancelled",
}


def _hex(value: Any) -> str:
    if hasattr(value, "hex"):
        result = value.hex()
        return result if result.startswith("0x") else f"0x{result}"

    return str(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return _hex(value)

    if hasattr(value, "hex") and not isinstance(value, str):
        return _hex(value)

    if isinstance(value, dict):
        return {
            str(key): _json_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def _utc_timestamp(timestamp: int) -> datetime:
    return datetime.utcfromtimestamp(int(timestamp))


def _normalize_key(value: Any) -> str:
    return _hex(value).lower()


def _build_recovery_lookup(db: Session) -> dict[str, str]:
    """
    Maps on-chain keccak(recovery_id) values to database recovery IDs.
    """
    lookup: dict[str, str] = {}

    recoveries = db.scalars(
        select(RecoveryRequest.id)
    ).all()

    for recovery_id in recoveries:
        key = Web3.keccak(text=recovery_id)
        lookup[_normalize_key(key)] = recovery_id

    return lookup


def _rebuild_recovery_projections(
    db: Session,
    chain_id: int,
    contract_address: str,
) -> int:
    """
    Rebuild all projections for this contract from stored event history.

    This is intentionally deterministic: replaying the same event history
    produces the same projection state.
    """
    db.execute(
        delete(BlockchainRecoveryProjection).where(
            BlockchainRecoveryProjection.chain_id == chain_id,
            BlockchainRecoveryProjection.contract_address == contract_address,
        )
    )
    db.flush()

    recovery_lookup = _build_recovery_lookup(db)

    events = db.scalars(
        select(BlockchainEvent)
        .where(
            BlockchainEvent.chain_id == chain_id,
            BlockchainEvent.contract_address == contract_address,
            BlockchainEvent.event_name.in_(RECOVERY_EVENTS),
        )
        .order_by(
            BlockchainEvent.block_number.asc(),
            BlockchainEvent.transaction_index.asc(),
            BlockchainEvent.log_index.asc(),
        )
    ).all()

    projections: dict[str, BlockchainRecoveryProjection] = {}

    for event in events:
        args = event.event_args or {}
        raw_key = args.get("recoveryKey")

        if not raw_key:
            continue

        recovery_key = _normalize_key(raw_key)

        projection = projections.get(recovery_key)

        if projection is None:
            projection = BlockchainRecoveryProjection(
                id=uuid.uuid4().hex,
                chain_id=chain_id,
                contract_address=contract_address,
                recovery_key=recovery_key,
                recovery_id=recovery_lookup.get(recovery_key),
                state="UNKNOWN",
                approvals=0,
                last_event_block=event.block_number,
                last_event_transaction=event.transaction_hash,
                updated_at=datetime.utcnow(),
            )
            projections[recovery_key] = projection

        projection.last_event_block = event.block_number
        projection.last_event_transaction = event.transaction_hash
        projection.updated_at = datetime.utcnow()

        if event.event_name == "RecoveryRequested":
            projection.state = "REQUESTED"

            policy_key = args.get("policyKey")
            if policy_key:
                projection.policy_key = str(policy_key).lower()

            requester = args.get("requester")
            if requester:
                projection.requester = str(requester)

            execute_after = args.get("executeAfter")
            if execute_after is not None:
                projection.execute_after = _utc_timestamp(
                    int(execute_after)
                )

            expires_at = args.get("expiresAt")
            if expires_at is not None:
                projection.expires_at = _utc_timestamp(
                    int(expires_at)
                )

            projection.requested_at = (
                event.block_timestamp
            )

        elif event.event_name == "ApprovalSubmitted":
            projection.approvals = int(
                args.get("approvals", projection.approvals)
            )

        elif event.event_name == "RecoveryExecuted":
            projection.state = "EXECUTED"
            projection.completed_at = event.block_timestamp

            artifact_hash = args.get("artifactHash")
            if artifact_hash:
                projection.artifact_hash = str(
                    artifact_hash
                ).lower()

        elif event.event_name == "RecoveryCancelled":
            projection.state = "CANCELLED"
            projection.cancelled_at = event.block_timestamp

            cancelled_by = args.get("cancelledBy")
            if cancelled_by:
                projection.cancelled_by = str(cancelled_by)

    for projection in projections.values():
        db.add(projection)

    db.flush()
    return len(projections)


def _sync_contract_events_unlocked(
    db: Session,
    max_blocks: int | None = None,
) -> dict[str, Any]:
    rpc_url = settings.blockchain_rpc_url
    configured_chain_id = int(settings.blockchain_chain_id)
    contract_address = (
        settings.blockchain_verifying_contract_address
    )

    if not Web3.is_address(contract_address):
        raise ValueError(
            "The configured blockchain contract address is invalid."
        )

    web3 = Web3(
        Web3.HTTPProvider(
            rpc_url,
            request_kwargs={"timeout": 30},
        )
    )

    if not web3.is_connected():
        raise ConnectionError(
            "Could not connect to the configured blockchain RPC."
        )

    actual_chain_id = int(web3.eth.chain_id)

    if actual_chain_id != configured_chain_id:
        raise ValueError(
            f"Wrong blockchain network. Expected chain "
            f"{configured_chain_id}, received {actual_chain_id}."
        )

    address = Web3.to_checksum_address(contract_address)

    contract = web3.eth.contract(
        address=address,
        abi=EVENT_ABI,
    )

    confirmations = max(
        0,
        int(os.getenv("BLOCKCHAIN_INDEXER_CONFIRMATIONS", "3")),
    )

    chunk_size = max(
        1,
        int(os.getenv("BLOCKCHAIN_INDEXER_CHUNK_SIZE", "500")),
    )

    reorg_window = max(
        1,
        int(os.getenv("BLOCKCHAIN_INDEXER_REORG_WINDOW", "12")),
    )

    start_block = max(
        0,
        int(os.getenv("BLOCKCHAIN_INDEXER_START_BLOCK", "0")),
    )

    latest_block = int(web3.eth.block_number)
    confirmed_block = latest_block - confirmations

    if confirmed_block < start_block:
        return {
            "status": "waiting_for_confirmations",
            "latest_block": latest_block,
            "confirmed_block": confirmed_block,
            "indexed_events": 0,
            "reorg_detected": False,
        }

    checkpoint = db.scalar(
        select(BlockchainSyncCheckpoint).where(
            BlockchainSyncCheckpoint.chain_id == configured_chain_id,
            BlockchainSyncCheckpoint.contract_address == address,
        )
    )

    if checkpoint is None:
        checkpoint = BlockchainSyncCheckpoint(
            id=uuid.uuid4().hex,
            chain_id=configured_chain_id,
            contract_address=address,
            last_processed_block=start_block - 1,
        )
        db.add(checkpoint)
        db.flush()

    reorg_detected = False

    # Verify the last indexed block against the canonical chain.
    if (
        checkpoint.last_processed_block >= start_block
        and checkpoint.last_block_hash
    ):
        canonical_block = web3.eth.get_block(
            checkpoint.last_processed_block
        )

        canonical_hash = _hex(
            canonical_block["hash"]
        )

        if canonical_hash.lower() != checkpoint.last_block_hash.lower():
            reorg_detected = True

            rewind_to = max(
                start_block - 1,
                checkpoint.last_processed_block - reorg_window,
            )

            db.execute(
                delete(BlockchainEvent).where(
                    BlockchainEvent.chain_id == configured_chain_id,
                    BlockchainEvent.contract_address == address,
                    BlockchainEvent.block_number > rewind_to,
                )
            )

            checkpoint.last_processed_block = rewind_to

            if rewind_to >= start_block:
                rewind_block = web3.eth.get_block(rewind_to)
                checkpoint.last_block_hash = _hex(
                    rewind_block["hash"]
                )
            else:
                checkpoint.last_block_hash = None

            db.flush()

    next_block = max(
        start_block,
        checkpoint.last_processed_block + 1,
    )

    indexed_count = 0
    processed_blocks = 0
    processed_until = checkpoint.last_processed_block

    while next_block <= confirmed_block:
        remaining = (
            max_blocks - processed_blocks
            if max_blocks is not None
            else chunk_size
        )

        if remaining <= 0:
            break

        blocks_this_chunk = min(chunk_size, remaining)

        end_block = min(
            next_block + blocks_this_chunk - 1,
            confirmed_block,
        )

        for event_name in [
            "PolicyRegistered",
            "PolicyStatusChanged",
            "ShareCommitmentsUpdated",
            "AssetCommitmentsRegistered",
            "RecoveryRequested",
            "ApprovalSubmitted",
            "RecoveryExecuted",
            "RecoveryCancelled",
        ]:
            event_factory = getattr(
                contract.events,
                event_name,
            )

            event_logs = event_factory().get_logs(
                from_block=next_block,
                to_block=end_block,
            )

            for log in event_logs:
                transaction_hash = _hex(
                    log["transactionHash"]
                )

                log_index = int(log["logIndex"])

                existing = db.scalar(
                    select(BlockchainEvent.id).where(
                        BlockchainEvent.chain_id == configured_chain_id,
                        BlockchainEvent.contract_address == address,
                        BlockchainEvent.transaction_hash == transaction_hash,
                        BlockchainEvent.log_index == log_index,
                    )
                )

                if existing is not None:
                    continue

                block_number = int(log["blockNumber"])
                block = web3.eth.get_block(block_number)
                timestamp = _utc_timestamp(
                    int(block["timestamp"])
                )

                event_record = BlockchainEvent(
                    id=uuid.uuid4().hex,
                    chain_id=configured_chain_id,
                    contract_address=address,
                    block_number=block_number,
                    block_hash=_hex(log["blockHash"]),
                    transaction_hash=transaction_hash,
                    transaction_index=int(log["transactionIndex"]),
                    log_index=log_index,
                    event_name=event_name,
                    event_args=_json_value(dict(log["args"])),
                    block_timestamp=timestamp,
                )

                db.add(event_record)
                indexed_count += 1

        db.flush()

        end_block_data = web3.eth.get_block(end_block)

        checkpoint.last_processed_block = end_block
        checkpoint.last_block_hash = _hex(
            end_block_data["hash"]
        )
        checkpoint.updated_at = datetime.utcnow()

        db.commit()

        processed_blocks += end_block - next_block + 1
        processed_until = end_block
        next_block = end_block + 1

    # Always rebuild from the stored event history. This also repairs
    # projections after a reorganization or a previously interrupted run.
    projection_count = _rebuild_recovery_projections(
        db=db,
        chain_id=configured_chain_id,
        contract_address=address,
    )

    checkpoint.updated_at = datetime.utcnow()
    db.commit()

    return {
        "status": "completed",
        "chain_id": configured_chain_id,
        "contract_address": address,
        "latest_block": latest_block,
        "confirmed_block": confirmed_block,
        "last_processed_block": processed_until,
        "blocks_processed_this_run": processed_blocks,
        "indexed_events": indexed_count,
        "recovery_projections_rebuilt": projection_count,
        "reorg_detected": reorg_detected,
    }


def sync_contract_events(
    db: Session,
    max_blocks: int | None = None,
) -> dict[str, Any]:
    """
    Synchronize one contract while holding a PostgreSQL advisory lock.

    The lock uses a dedicated database connection. This connection remains
    checked out for the entire synchronization, even when the indexer's
    normal database session commits individual chunks.
    """

    lock_key = (
        f"deaddrop:indexer:"
        f"{settings.blockchain_chain_id}:"
        f"{settings.blockchain_verifying_contract_address.lower()}"
    )

    bind = db.get_bind()

    # SQLite and other non-PostgreSQL databases use the normal sync path.
    if bind.dialect.name != "postgresql":
        return _sync_contract_events_unlocked(
            db=db,
            max_blocks=max_blocks,
        )

    lock_sql = text(
        "SELECT pg_try_advisory_lock("
        "hashtextextended(:lock_key, 0)"
        ")"
    )

    unlock_sql = text(
        "SELECT pg_advisory_unlock("
        "hashtextextended(:lock_key, 0)"
        ")"
    )

    # Keep this physical connection reserved until the lock is released.
    with bind.connect() as lock_connection:
        acquired = bool(
            lock_connection.execute(
                lock_sql,
                {"lock_key": lock_key},
            ).scalar()
        )

        if not acquired:
            return {
                "status": "already_running",
                "message": (
                    "Another blockchain synchronization is already "
                    "running for this network and contract."
                ),
            }

        # The advisory lock is session-level, so committing this transaction
        # does not release the lock. It does keep the connection pinned here.
        lock_connection.commit()

        try:
            return _sync_contract_events_unlocked(
                db=db,
                max_blocks=max_blocks,
            )

        finally:
            try:
                unlocked = bool(
                    lock_connection.execute(
                        unlock_sql,
                        {"lock_key": lock_key},
                    ).scalar()
                )

                lock_connection.commit()

                if not unlocked:
                    raise RuntimeError(
                        "PostgreSQL advisory lock could not be released."
                    )

            except Exception:
                # If unlocking fails, invalidate the physical connection.
                # Closing a PostgreSQL session releases its session-level lock.
                lock_connection.invalidate()
                raise
