
from unittest.mock import MagicMock, patch

from app.blockchain import indexer


def make_postgres_db(lock_acquired: bool):
    db = MagicMock()

    bind = MagicMock()
    bind.dialect.name = "postgresql"

    lock_connection = MagicMock()
    lock_connection.execute.return_value.scalar.return_value = (
        lock_acquired
    )

    connection_context = MagicMock()
    connection_context.__enter__.return_value = lock_connection
    connection_context.__exit__.return_value = False

    bind.connect.return_value = connection_context
    db.get_bind.return_value = bind

    return db, bind, lock_connection


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
    sync.assert_called_once_with(
        db=db,
        max_blocks=None,
    )


def test_postgres_lock_prevents_duplicate_sync():
    db, bind, lock_connection = make_postgres_db(False)

    result = indexer.sync_contract_events(db)

    assert result["status"] == "already_running"
    assert "already running" in result["message"].lower()

    # The dedicated lock connection is used.
    bind.connect.assert_called_once()

    # No actual indexing should happen when the lock is unavailable.
    lock_connection.commit.assert_not_called()


def test_postgres_lock_is_released_after_sync():
    db, bind, lock_connection = make_postgres_db(True)

    expected = {
        "status": "completed",
        "indexed_events": 2,
    }

    with patch.object(
        indexer,
        "_sync_contract_events_unlocked",
        return_value=expected,
    ) as sync:
        result = indexer.sync_contract_events(
            db,
            max_blocks=100,
        )

    assert result == expected

    sync.assert_called_once_with(
        db=db,
        max_blocks=100,
    )

    # One commit after acquisition, one after release.
    assert lock_connection.commit.call_count == 2

    # Both lock operations use the same dedicated connection.
    assert lock_connection.execute.call_count == 2

    bind.connect.assert_called_once()
