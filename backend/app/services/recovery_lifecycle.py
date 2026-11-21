
from __future__ import annotations

from datetime import datetime

from app.models.recovery import RecoveryRequest


ACTIVE_RECOVERY_STATUSES = {"PENDING", "APPROVED"}


def expire_recovery_if_needed(
    recovery: RecoveryRequest,
    now: datetime | None = None,
) -> bool:
    """
    Mark an active recovery request as expired when its
    expiry deadline has passed.

    Returns True if the status was changed.
    """
    current_time = now or datetime.utcnow()

    if recovery.status not in ACTIVE_RECOVERY_STATUSES:
        return False

    if recovery.expires_at is None:
        return False

    if recovery.expires_at > current_time:
        return False

    recovery.status = "EXPIRED"
    return True


def recovery_release_block_reason(
    recovery: RecoveryRequest,
    now: datetime | None = None,
) -> str | None:
    """
    Return a reason why encrypted recovery shares cannot
    currently be released.

    Return None when release is allowed.
    """
    current_time = now or datetime.utcnow()

    if recovery.status == "EXPIRED":
        return "This recovery request has expired."

    if recovery.status == "CANCELLED":
        return "This recovery request has been cancelled."

    if recovery.status == "EXECUTED":
        return "This recovery request has already been executed."

    if recovery.status != "APPROVED":
        return "The recovery request has not received sufficient approvals."

    if recovery.expires_at is not None:
        if recovery.expires_at <= current_time:
            recovery.status = "EXPIRED"
            return "This recovery request has expired."

    if recovery.execute_after is None:
        return "The recovery timelock has not been initialized."

    if current_time < recovery.execute_after:
        remaining_seconds = int(
            (recovery.execute_after - current_time).total_seconds()
        )

        return (
            "The recovery timelock is still active. "
            f"Please wait approximately {remaining_seconds} seconds."
        )

    return None
