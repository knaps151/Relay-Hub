from __future__ import annotations

import logging

from sqlalchemy import inspect, text

from app.db import engine

logger = logging.getLogger(__name__)


def ensure_schema() -> None:
    """Add missing columns for existing SQLite DBs (create_all won't alter)."""
    insp = inspect(engine)
    if "sites" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("sites")}
    with engine.begin() as conn:
        if "region" not in cols:
            logger.info("Adding sites.region column")
            conn.execute(text("ALTER TABLE sites ADD COLUMN region VARCHAR(120) DEFAULT ''"))
