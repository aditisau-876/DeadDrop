
from unittest.mock import MagicMock, patch

from app.blockchain import indexer


def test_non_postgres_uses_normal_sync_path():
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "sqlite"

    expected = {
        "status": "completed",
        "indexed_events": 0,
    }

    with patch.object(
        indexer,
        "_sync_contract_events_unlocked",
        return_value=expected,
    ) as sync:
        result = indexer.sync_contract_events(db)

    assert result == expected
    sync.assert_called_once_with(db=db, max_blocks=None)


def test_postgres_lock_prevents_duplicate_sync():
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "postgresql"
    db.execute.return_value.scalar.return_value = False

    result = indexer.sync_contract_events(db)

    assert result["status"] == "already_running"
    assert "already running" in result["message"].lower()


def test_postgres_lock_is_released_after_sync():
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "postgresql"
    db.execute.return_value.scalar.return_value = True

    expected = {
        "status": "completed",
        "indexed_events": 2,
    }

    with patch.object(
        indexer,
        "_sync_contract_events_unlocked",
        return_value=expected,
    ):
        result = indexer.sync_contract_events(db)

    assert result == expected

    # First execute acquires; second execute releases.
    assert db.execute.call_count == 2
    db.commit.assert_called_once()
