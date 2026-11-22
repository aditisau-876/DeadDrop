"""Add blockchain event indexing tables.

Revision ID: c4d6e8f01234
Revises: b3c5d7e9f102
"""

from alembic import op
import sqlalchemy as sa


revision = "c4d6e8f01234"
down_revision = "b3c5d7e9f102"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "blockchain_events",
        sa.Column(
            "id",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "chain_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "contract_address",
            sa.String(length=42),
            nullable=False,
        ),
        sa.Column(
            "block_number",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "block_hash",
            sa.String(length=66),
            nullable=False,
        ),
        sa.Column(
            "transaction_hash",
            sa.String(length=66),
            nullable=False,
        ),
        sa.Column(
            "transaction_index",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "log_index",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "event_name",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "event_args",
            sa.JSON(),
            nullable=False,
        ),
        sa.Column(
            "block_timestamp",
            sa.DateTime(),
            nullable=True,
        ),
        sa.Column(
            "indexed_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "chain_id",
            "contract_address",
            "transaction_hash",
            "log_index",
            name="uq_blockchain_event_log",
        ),
    )

    op.create_index(
        "ix_blockchain_events_chain_id",
        "blockchain_events",
        ["chain_id"],
    )

    op.create_index(
        "ix_blockchain_events_contract_address",
        "blockchain_events",
        ["contract_address"],
    )

    op.create_index(
        "ix_blockchain_events_block_number",
        "blockchain_events",
        ["block_number"],
    )

    op.create_index(
        "ix_blockchain_events_event_name",
        "blockchain_events",
        ["event_name"],
    )

    op.create_table(
        "blockchain_sync_checkpoints",
        sa.Column(
            "id",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "chain_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "contract_address",
            sa.String(length=42),
            nullable=False,
        ),
        sa.Column(
            "last_processed_block",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "last_block_hash",
            sa.String(length=66),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "chain_id",
            "contract_address",
            name="uq_blockchain_sync_network_contract",
        ),
    )


def downgrade() -> None:
    op.drop_table("blockchain_sync_checkpoints")

    op.drop_index(
        "ix_blockchain_events_event_name",
        table_name="blockchain_events",
    )

    op.drop_index(
        "ix_blockchain_events_block_number",
        table_name="blockchain_events",
    )

    op.drop_index(
        "ix_blockchain_events_contract_address",
        table_name="blockchain_events",
    )

    op.drop_index(
        "ix_blockchain_events_chain_id",
        table_name="blockchain_events",
    )

    op.drop_table("blockchain_events")