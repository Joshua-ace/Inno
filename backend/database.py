"""
SQLite database initialization and connection management.
Uses aiosqlite for async operations.
"""

import aiosqlite
import os
from config import settings

DB_PATH = os.path.join(os.path.dirname(__file__), settings.database_path)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL CHECK(scan_type IN ('url', 'message')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    risk_score INTEGER NOT NULL CHECK(risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL,
    classification TEXT NOT NULL,
    input_preview TEXT,
    findings TEXT NOT NULL,
    provider_status TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    ai_explanation TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
"""


async def init_db():
    """Create tables if they do not exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def get_db():
    """Yield a database connection for use in route dependencies."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()
