
from datetime import datetime

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker

from app.db.database import Base
from app.models.blockchain_event import BlockchainEvent
from app.models.blockchain_projection import (
    BlockchainRecoveryProjection,
)
from app.blockchain.indexer import (
    _rebuild_recovery_projections,
)


def test_replay_removes_orphaned_execution_state():
    engine = create_engine("sqlite:///:memory:")

    Base.metadata.create_all(engine)

    Session = sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )

    db = Session()

    try:
        chain_id = 31337
        address = "0x0000000000000000000000000000000000000001"
        recovery_key = "0x" + ("11" * 32)

        common = {
            "chain_id": chain_id,
            "contract_address": address,
            "block_timestamp": datetime(2026, 1, 1),
        }

        db.add_all([
            BlockchainEvent(
                id="event-request",
                block_number=10,
                block_hash="0x" + ("aa" * 32),
                transaction_hash="0x" + ("01" * 32),
                transaction_index=0,
                log_index=0,
                event_name="RecoveryRequested",
                event_args={
                    "recoveryKey": recovery_key,
                    "policyKey": "0x" + ("22" * 32),
                    "requester": address,
                    "executeAfter": 1767225660,
                    "expiresAt": 1767312000,
                },
                **common,
            ),
            BlockchainEvent(
                id="event-approval",
                block_number=11,
                block_hash="0x" + ("bb" * 32),
                transaction_hash="0x" + ("02" * 32),
                transaction_index=0,
                log_index=0,
                event_name="ApprovalSubmitted",
                event_args={
                    "recoveryKey": recovery_key,
                    "trustee": address,
                    "approvals": 2,
                },
                **common,
            ),
            BlockchainEvent(
                id="event-execution",
                block_number=12,
                block_hash="0x" + ("cc" * 32),
                transaction_hash="0x" + ("03" * 32),
                transaction_index=0,
                log_index=0,
                event_name="RecoveryExecuted",
                event_args={
                    "recoveryKey": recovery_key,
                    "artifactHash": "0x" + ("33" * 32),
                },
                **common,
            ),
        ])

        db.commit()

        count = _rebuild_recovery_projections(
            db,
            chain_id,
            address,
        )

        assert count == 1

        projection = db.query(
            BlockchainRecoveryProjection
        ).one()

        assert projection.state == "EXECUTED"
        assert projection.approvals == 2

        # Simulate a chain reorganization that removes the
        # execution event while retaining the earlier events.
        db.execute(
            delete(BlockchainEvent).where(
                BlockchainEvent.id == "event-execution"
            )
        )
        db.commit()

        count = _rebuild_recovery_projections(
            db,
            chain_id,
            address,
        )

        assert count == 1

        projection = db.query(
            BlockchainRecoveryProjection
        ).one()

        assert projection.state == "REQUESTED"
        assert projection.approvals == 2
        assert projection.completed_at is None
        assert projection.artifact_hash is None
        assert projection.last_event_block == 11

    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
