from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """
    Base class for all DeadDrop SQLAlchemy models.
    """

    pass


# SQLAlchemy database engine
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
)


# Database session factory
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """
    Provide a database session for FastAPI endpoints.
    """
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()