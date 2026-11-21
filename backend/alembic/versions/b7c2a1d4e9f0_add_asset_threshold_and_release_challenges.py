"""add asset threshold and one-time share release challenges

Revision ID: b7c2a1d4e9f0
Revises: 555233b92983
Create Date: 2026-11-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b7c2a1d4e9f0"
down_revision: Union[str, Sequence[str], None] = "555233b92983"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The ORM model already defines threshold=3. This migration makes
    # that field explicit in databases created from the earlier schema.
    op.add_column(
        "protected_assets",
        sa.Column("threshold", sa.Integer(), nullable=False, server_default="3"),
    )
    op.create_table(
        "share_release_challenges",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("recovery_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("trustee_id", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["recovery_id"], ["recovery_requests.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["protected_assets.id"]),
        sa.ForeignKeyConstraint(["trustee_id"], ["trustees.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_share_release_challenges_recovery_id",
        "share_release_challenges",
        ["recovery_id"],
    )
    op.create_index(
        "ix_share_release_challenges_trustee_id",
        "share_release_challenges",
        ["trustee_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_share_release_challenges_trustee_id",
        table_name="share_release_challenges",
    )
    op.drop_index(
        "ix_share_release_challenges_recovery_id",
        table_name="share_release_challenges",
    )
    op.drop_table("share_release_challenges")
    op.drop_column("protected_assets", "threshold")
