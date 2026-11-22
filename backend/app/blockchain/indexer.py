from __future__ import annotations

import os
import uuid

from datetime import datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from web3 import Web3

from app.blockchain.client import BlockchainClient
from app.core.config import settings
from app.models.blockchain_event import (
    BlockchainEvent,
    BlockchainSyncCheckpoint,
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


def _recovery_for_key(
    db: Session,
    recovery_key: str,
) -> RecoveryRequest | None:
    normalized_key = recovery_key.lower()

    recoveries = db.scalars(
        select(RecoveryRequest)
    ).all()

    for recovery in recoveries:
        expected = Web3.keccak(
            text=recovery.id
        ).hex().lower()

        if expected == normalized_key:
            return recovery

    return None


def _apply_recovery_event(
    db: Session,
    event_name: str,
    args: dict[str, Any],
    block_timestamp: datetime | None,
) -> None:
    recovery_key = args.get("recoveryKey")

    if recovery_key is None:
        return

    recovery = _recovery_for_key(
        db,
        _hex(recovery_key),
    )

    if recovery is None:
        return

    if event_name == "RecoveryRequested":
        execute_after = args.get("executeAfter")
        expires_at = args.get("expiresAt")

        if execute_after is not None:
            recovery.execute_after = _utc_timestamp(
                execute_after
            )

        if expires_at is not None:
            recovery.expires_at = _utc_timestamp(
                expires_at
            )

    elif event_name == "ApprovalSubmitted":
        recovery.approvals = int(
            args.get("approvals", recovery.approvals)
        )


    elif event_name == "RecoveryExecuted":
        recovery.status = "EXECUTED"
        recovery.completed_at = (
            block_timestamp or datetime.utcnow()
        )

    elif event_name == "RecoveryCancelled":
        recovery.status = "CANCELLED"
        recovery.cancelled_at = (
            block_timestamp or datetime.utcnow()
        )
        recovery.cancellation_reason = (
            "Cancelled on-chain."
        )


def sync_contract_events(
    db: Session,
    max_blocks: int | None = None,
) -> dict[str, Any]:
    rpc_url = settings.blockchain_rpc_url
    configured_chain_id = settings.blockchain_chain_id
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

    address = Web3.to_checksum_address(
        contract_address
    )

    contract = web3.eth.contract(
        address=address,
        abi=EVENT_ABI,
    )

    confirmations = max(
        0,
        int(os.getenv(
            "BLOCKCHAIN_INDEXER_CONFIRMATIONS",
            "3",
        )),
    )

    chunk_size = max(
        1,
        int(os.getenv(
            "BLOCKCHAIN_INDEXER_CHUNK_SIZE",
            "500",
        )),
    )

    reorg_window = max(
        1,
        int(os.getenv(
            "BLOCKCHAIN_INDEXER_REORG_WINDOW",
            "12",
        )),
    )

    start_block = max(
        0,
        int(os.getenv(
            "BLOCKCHAIN_INDEXER_START_BLOCK",
            "0",
        )),
    )

    latest_block = int(web3.eth.block_number)
    confirmed_block = latest_block - confirmations

    if confirmed_block < start_block:
        return {
            "status": "waiting_for_confirmations",
            "latest_block": latest_block,
            "confirmed_block": confirmed_block,
            "indexed_events": 0,
        }

    checkpoint = db.scalar(
        select(BlockchainSyncCheckpoint).where(
            BlockchainSyncCheckpoint.chain_id
            == configured_chain_id,
            BlockchainSyncCheckpoint.contract_address
            == address,
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

    # Verify the checkpoint block before continuing.
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

        if canonical_hash.lower() != (
            checkpoint.last_block_hash.lower()
        ):
            rewind_to = max(
                start_block - 1,
                checkpoint.last_processed_block
                - reorg_window,
            )

            db.execute(
                delete(BlockchainEvent).where(
                    BlockchainEvent.chain_id
                    == configured_chain_id,
                    BlockchainEvent.contract_address
                    == address,
                    BlockchainEvent.block_number
                    > rewind_to,
                )
            )

            checkpoint.last_processed_block = rewind_to

            if rewind_to >= start_block:
                rewind_block = web3.eth.get_block(
                    rewind_to
                )
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
    processed_until = checkpoint.last_processed_block

    while next_block <= confirmed_block:
        end_block = min(
            next_block + chunk_size - 1,
            confirmed_block,
        )

        for event_name in [
            "PolicyRegistered",
            "PolicyStatusChanged",
            "ShareCommitmentsUpdated",
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

                log_index = int(
                    log["logIndex"]
                )

                existing = db.scalar(
                    select(BlockchainEvent.id).where(
                        BlockchainEvent.chain_id
                        == configured_chain_id,
                        BlockchainEvent.contract_address
                        == address,
                        BlockchainEvent.transaction_hash
                        == transaction_hash,
                        BlockchainEvent.log_index
                        == log_index,
                    )
                )

                if existing is not None:
                    continue

                args = dict(log["args"])

                block = web3.eth.get_block(
                    int(log["blockNumber"])
                )

                timestamp = _utc_timestamp(
                    int(block["timestamp"])
                )

                event_record = BlockchainEvent(
                    id=uuid.uuid4().hex,
                    chain_id=configured_chain_id,
                    contract_address=address,
                    block_number=int(
                        log["blockNumber"]
                    ),
                    block_hash=_hex(
                        log["blockHash"]
                    ),
                    transaction_hash=transaction_hash,
                    transaction_index=int(
                        log["transactionIndex"]
                    ),
                    log_index=log_index,
                    event_name=event_name,
                    event_args=_json_value(args),
                    block_timestamp=timestamp,
                )

                db.add(event_record)

                _apply_recovery_event(
                    db,
                    event_name,
                    args,
                    timestamp,
                )

                indexed_count += 1

        # Commit each completed chunk. This keeps large syncs manageable.
        db.flush()

        end_block_data = web3.eth.get_block(
            end_block
        )

        checkpoint.last_processed_block = end_block
        checkpoint.last_block_hash = _hex(
            end_block_data["hash"]
        )
        checkpoint.updated_at = datetime.utcnow()

        db.commit()

        processed_until = end_block
        next_block = end_block + 1

        if (
            max_blocks is not None
            and processed_until - start_block + 1
            >= max_blocks
        ):
            break

    return {
        "status": "completed",
        "chain_id": configured_chain_id,
        "contract_address": address,
        "latest_block": latest_block,
        "confirmed_block": confirmed_block,
        "last_processed_block": processed_until,
        "indexed_events": indexed_count,
    }