
"""Add audit logs.

Revision ID: b3c5d7e9f102
Revises: a2b4c6d8e0f1
"""

from alembic import op
import sqlalchemy as sa


revision = "b3c5d7e9f102"
down_revision = "a2b4c6d8e0f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column(
            "id",
            sa.String(length=64),
            primary_key=True,
        ),
        sa.Column(
            "actor_user_id",
            sa.String(length=64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "action",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "route",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "status_code",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "ip_address",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "user_agent",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "request_id",
            sa.String(length=64),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
        ),
    )

    op.create_index(
        "ix_audit_logs_actor_user_id",
        "audit_logs",
        ["actor_user_id"],
    )

    op.create_index(
        "ix_audit_logs_created_at",
        "audit_logs",
        ["created_at"],
    )

    op.create_index(
        "ix_audit_logs_created_at_id",
        "audit_logs",
        ["created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_logs_created_at_id",
        table_name="audit_logs",
    )

    op.drop_index(
        "ix_audit_logs_created_at",
        table_name="audit_logs",
    )

    op.drop_index(
        "ix_audit_logs_actor_user_id",
        table_name="audit_logs",
    )

    op.drop_table("audit_logs")
