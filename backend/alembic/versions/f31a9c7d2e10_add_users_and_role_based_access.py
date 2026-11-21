"""add users and role-based access ownership links

Revision ID: f31a9c7d2e10
Revises: e7e317897a77
Create Date: 2026-11-21
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "f31a9c7d2e10"
down_revision: Union[str, Sequence[str], None] = "e7e317897a77"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("users",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("full_name", sa.String(length=120), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False, server_default="owner"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.add_column("trustees", sa.Column("user_id", sa.String(length=64), nullable=True))
    op.create_foreign_key("fk_trustees_user_id_users", "trustees", "users", ["user_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_trustees_user_id", "trustees", ["user_id"], unique=True)
    op.add_column("policies", sa.Column("owner_user_id", sa.String(length=64), nullable=True))
    op.create_foreign_key("fk_policies_owner_user_id_users", "policies", "users", ["owner_user_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_policies_owner_user_id", "policies", ["owner_user_id"])
    op.add_column("protected_assets", sa.Column("owner_user_id", sa.String(length=64), nullable=True))
    op.create_foreign_key("fk_protected_assets_owner_user_id_users", "protected_assets", "users", ["owner_user_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_protected_assets_owner_user_id", "protected_assets", ["owner_user_id"])

def downgrade() -> None:
    op.drop_index("ix_protected_assets_owner_user_id", table_name="protected_assets")
    op.drop_constraint("fk_protected_assets_owner_user_id_users", "protected_assets", type_="foreignkey")
    op.drop_column("protected_assets", "owner_user_id")
    op.drop_index("ix_policies_owner_user_id", table_name="policies")
    op.drop_constraint("fk_policies_owner_user_id_users", "policies", type_="foreignkey")
    op.drop_column("policies", "owner_user_id")
    op.drop_index("ix_trustees_user_id", table_name="trustees")
    op.drop_constraint("fk_trustees_user_id_users", "trustees", type_="foreignkey")
    op.drop_column("trustees", "user_id")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
