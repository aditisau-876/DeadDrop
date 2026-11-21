
from datetime import datetime, timedelta
from types import SimpleNamespace

from app.services.recovery_lifecycle import (
    expire_recovery_if_needed,
    recovery_release_block_reason,
)


def make_recovery(**overrides):
    values = {
        "status": "PENDING",
        "expires_at": None,
        "execute_after": None,
    }

    values.update(overrides)

    return SimpleNamespace(**values)


def test_pending_recovery_expires():
    now = datetime.utcnow()

    recovery = make_recovery(
        status="PENDING",
        expires_at=now - timedelta(seconds=1),
    )

    changed = expire_recovery_if_needed(
        recovery,
        now,
    )

    assert changed is True
    assert recovery.status == "EXPIRED"


def test_approved_recovery_can_expire():
    now = datetime.utcnow()

    recovery = make_recovery(
        status="APPROVED",
        expires_at=now - timedelta(seconds=1),
    )

    changed = expire_recovery_if_needed(
        recovery,
        now,
    )

    assert changed is True
    assert recovery.status == "EXPIRED"


def test_recovery_without_expiry_does_not_expire():
    recovery = make_recovery(
        status="PENDING",
        expires_at=None,
    )

    assert expire_recovery_if_needed(recovery) is False
    assert recovery.status == "PENDING"


def test_release_is_blocked_before_timelock():
    now = datetime.utcnow()

    recovery = make_recovery(
        status="APPROVED",
        execute_after=now + timedelta(minutes=10),
    )

    reason = recovery_release_block_reason(
        recovery,
        now,
    )

    assert reason is not None
    assert "timelock" in reason.lower()


def test_release_is_allowed_after_timelock():
    now = datetime.utcnow()

    recovery = make_recovery(
        status="APPROVED",
        execute_after=now - timedelta(seconds=1),
    )

    reason = recovery_release_block_reason(
        recovery,
        now,
    )

    assert reason is None


def test_release_is_blocked_when_not_approved():
    recovery = make_recovery(
        status="PENDING",
    )

    reason = recovery_release_block_reason(
        recovery
    )

    assert reason is not None


def test_cancelled_recovery_cannot_release():
    recovery = make_recovery(
        status="CANCELLED",
    )

    reason = recovery_release_block_reason(
        recovery
    )

    assert reason is not None
    assert "cancelled" in reason.lower()


def test_missing_timelock_is_not_allowed():
    recovery = make_recovery(
        status="APPROVED",
        execute_after=None,
    )

    reason = recovery_release_block_reason(
        recovery
    )

    assert reason is not None
