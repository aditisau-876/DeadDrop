"""Add rebuildable blockchain recovery projections.

Revision ID: d5e7f9012345
Revises: c4d6e8f01234
"""

from alembic import op
import sqlalchemy as sa


revision = "d5e7f9012345"
down_revision = "c4d6e8f01234"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "blockchain_recovery_projections",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("contract_address", sa.String(length=42), nullable=False),
        sa.Column("recovery_key", sa.String(length=66), nullable=False),
        sa.Column(
            "recovery_id",
            sa.String(length=64),
            sa.ForeignKey(
                "recovery_requests.id",
                ondelete="SET NULL",
            ),
            nullable=True,
        ),
        sa.Column("policy_key", sa.String(length=66), nullable=True),
        sa.Column("requester", sa.String(length=42), nullable=True),
        sa.Column(
            "state",
            sa.String(length=32),
            nullable=False,
            server_default="UNKNOWN",
        ),
        sa.Column(
            "approvals",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("execute_after", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("requested_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
        sa.Column("cancelled_by", sa.String(length=42), nullable=True),
        sa.Column("artifact_hash", sa.String(length=66), nullable=True),
        sa.Column("last_event_block", sa.Integer(), nullable=False),
        sa.Column(
            "last_event_transaction",
            sa.String(length=66),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "chain_id",
            "contract_address",
            "recovery_key",
            name="uq_chain_recovery_projection",
        ),
    )

    op.create_index(
        "ix_blockchain_recovery_projections_recovery_key",
        "blockchain_recovery_projections",
        ["recovery_key"],
    )

    op.create_index(
        "ix_blockchain_recovery_projections_state",
        "blockchain_recovery_projections",
        ["state"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_blockchain_recovery_projections_state",
        table_name="blockchain_recovery_projections",
    )

    op.drop_index(
        "ix_blockchain_recovery_projections_recovery_key",
        table_name="blockchain_recovery_projections",
    )

    op.drop_table("blockchain_recovery_projections")