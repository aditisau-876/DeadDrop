from __future__ import annotations

import asyncio
import logging
import os

from app.blockchain.indexer import sync_contract_events
from app.db.database import SessionLocal

logger = logging.getLogger(__name__)


def _run_sync_once() -> dict:
    db = SessionLocal()

    try:
        max_blocks = max(
            1,
            int(
                os.getenv(
                    "BLOCKCHAIN_SYNC_MAX_BLOCKS_PER_RUN",
                    "2000",
                )
            ),
        )

        return sync_contract_events(
            db=db,
            max_blocks=max_blocks,
        )

    finally:
        db.close()


async def blockchain_sync_loop() -> None:
    interval = max(
        15,
        int(
            os.getenv(
                "BLOCKCHAIN_SYNC_INTERVAL_SECONDS",
                "60",
            )
        ),
    )

    logger.info(
        "DeadDrop blockchain sync scheduler started. Interval: %s seconds",
        interval,
    )

    while True:
        try:
            result = await asyncio.to_thread(
                _run_sync_once
            )

            logger.info(
                "Blockchain sync result: %s",
                result,
            )

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.exception(
                "Automatic blockchain synchronization failed."
            )

        await asyncio.sleep(interval)


def automatic_sync_enabled() -> bool:
    return (
        os.getenv(
            "BLOCKCHAIN_AUTO_SYNC_ENABLED",
            "false",
        ).strip().lower()
        in {"1", "true", "yes", "on"}
    )