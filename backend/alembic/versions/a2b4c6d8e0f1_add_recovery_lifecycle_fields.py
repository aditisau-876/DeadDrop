
"""Add recovery lifecycle timestamps and status index.

Revision ID: a2b4c6d8e0f1
Revises: f31a9c7d2e10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a2b4c6d8e0f1"

down_revision: Union[str, Sequence[str], None] = "f31a9c7d2e10"

branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "recovery_requests",
        sa.Column(
            "expires_at",
            sa.DateTime(),
            nullable=True,
        ),
    )

    op.add_column(
        "recovery_requests",
        sa.Column(
            "execute_after",
            sa.DateTime(),
            nullable=True,
        ),
    )

    op.add_column(
        "recovery_requests",
        sa.Column(
            "cancelled_at",
            sa.DateTime(),
            nullable=True,
        ),
    )

    op.add_column(
        "recovery_requests",
        sa.Column(
            "cancellation_reason",
            sa.Text(),
            nullable=True,
        ),
    )

    op.add_column(
        "recovery_requests",
        sa.Column(
            "completed_at",
            sa.DateTime(),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_recovery_requests_status",
        "recovery_requests",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_recovery_requests_status",
        table_name="recovery_requests",
    )

    op.drop_column(
        "recovery_requests",
        "completed_at",
    )

    op.drop_column(
        "recovery_requests",
        "cancellation_reason",
    )

    op.drop_column(
        "recovery_requests",
        "cancelled_at",
    )

    op.drop_column(
        "recovery_requests",
        "execute_after",
    )

    op.drop_column(
        "recovery_requests",
        "expires_at",
    )
