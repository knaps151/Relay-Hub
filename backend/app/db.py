from __future__ import annotations

import logging
from collections.abc import Generator
from typing import TYPE_CHECKING

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

if TYPE_CHECKING:
    from sqlalchemy import Column

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _get_existing_columns(table_name: str) -> set[str]:
    """Get the set of existing column names for a table."""
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(table_name)}


def _add_column_if_missing(table_name: str, column: "Column", column_def: str) -> None:
    """Add a column to a table if it doesn't already exist. Idempotent."""
    existing = _get_existing_columns(table_name)
    if column.name not in existing:
        logger.info("Adding column %s.%s", table_name, column.name)
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_def}"))


def run_schema_upgrades() -> None:
    """
    Run idempotent schema upgrades. This is called at startup to add any new
    columns or tables needed by new features without dropping existing data.
    
    Each upgrade checks if the change is needed before applying it.
    """
    from app import models  # noqa: F401

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    # Create any missing tables (new tables added by later issues)
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            logger.info("Creating table: %s", table.name)
            table.create(engine)

    # Add missing columns to existing tables
    # Format: (table_name, column_name, SQL column definition)
    # Add new column migrations here as needed
    column_migrations: list[tuple[str, str, str]] = [
        ("sites", "region", "region VARCHAR(120) DEFAULT ''"),
    ]

    for table_name, column_name, column_def in column_migrations:
        existing = _get_existing_columns(table_name)
        if column_name not in existing:
            logger.info("Adding column %s.%s", table_name, column_name)
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_def}"))


def init_db() -> None:
    from app import models  # noqa: F401

    # Create all tables that don't exist
    Base.metadata.create_all(bind=engine)

    # Run any additional schema upgrades (column additions, etc.)
    run_schema_upgrades()
