
"""add durable share rotation attempts"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f6a8b2c4d901"
down_revision: Union[str, Sequence[str], None] = "d5e7f9012345"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "share_rotation_attempts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("previous_epoch", sa.Integer(), nullable=False),
        sa.Column("new_epoch", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="PREPARED",
        ),
        sa.Column(
            "transaction_hash",
            sa.String(length=66),
            nullable=True,
        ),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
        ),
    )

    op.create_index(
        "ix_share_rotation_attempts_policy_id",
        "share_rotation_attempts",
        ["policy_id"],
    )

    op.create_index(
        "ix_share_rotation_attempts_status",
        "share_rotation_attempts",
        ["status"],
    )

    op.create_index(
        "ix_share_rotation_attempts_transaction_hash",
        "share_rotation_attempts",
        ["transaction_hash"],
    )

    op.create_index(
        "ix_rotation_attempt_policy_status_epoch",
        "share_rotation_attempts",
        ["policy_id", "status", "previous_epoch"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_rotation_attempt_policy_status_epoch",
        table_name="share_rotation_attempts",
    )

    op.drop_index(
        "ix_share_rotation_attempts_transaction_hash",
        table_name="share_rotation_attempts",
    )

    op.drop_index(
        "ix_share_rotation_attempts_status",
        table_name="share_rotation_attempts",
    )

    op.drop_index(
        "ix_share_rotation_attempts_policy_id",
        table_name="share_rotation_attempts",
    )

    op.drop_table("share_rotation_attempts")
