"""merge policy tree and recovery challenge heads

Revision ID: e7e317897a77
Revises: 490b8462c31e, b7c2a1d4e9f0
Create Date: 2026-11-21 12:49:57.246899
"""
from typing import Sequence, Union

revision: str = "e7e317897a77"
down_revision: Union[str, Sequence[str], None] = (
    "490b8462c31e",
    "b7c2a1d4e9f0",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Merge migration branches; no schema operation is required."""
    pass


def downgrade() -> None:
    """No schema changes are reversed by this merge revision."""
    pass
