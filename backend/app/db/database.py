from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all DeadDrop SQLAlchemy models.

    Database connection configuration will be added later
    when PostgreSQL is configured.
    """

    pass