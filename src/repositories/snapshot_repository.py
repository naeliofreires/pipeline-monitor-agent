from __future__ import annotations

import logging
import sqlite3
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# `window_start` is the date (YYYY-MM-DD, UTC) the volume belongs to; `captured_at`
# is the ISO-8601 UTC instant the snapshot was taken. One row per (flow_id,
# window_start) — re-observing the same day upserts the latest count.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS metric_snapshots (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_id       INTEGER NOT NULL,
  window_start  TEXT    NOT NULL,
  record_count  INTEGER NOT NULL,
  captured_at   TEXT    NOT NULL,
  UNIQUE (flow_id, window_start)
);
CREATE INDEX IF NOT EXISTS idx_snapshot_lookup
  ON metric_snapshots (flow_id, window_start);
"""


class SnapshotRepository:
    """The only code that touches the SQLite metric-snapshot history."""

    def __init__(self, db_path: str) -> None:
        # ":memory:" (used by tests) has no parent directory to create.
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def save_snapshot(
        self, flow_id: int, window_start: str, record_count: int, captured_at: datetime
    ) -> None:
        """Record a flow's volume for a date window, replacing any earlier value for that day."""
        self._conn.execute(
            "INSERT INTO metric_snapshots (flow_id, window_start, record_count, captured_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT (flow_id, window_start) DO UPDATE SET "
            "record_count = excluded.record_count, captured_at = excluded.captured_at",
            (int(flow_id), str(window_start), int(record_count), captured_at.isoformat()),
        )
        self._conn.commit()

    def get_record_count(self, flow_id: int, window_start: str) -> int | None:
        """Return the stored volume for a flow's date window, or None if never captured."""
        cursor = self._conn.execute(
            "SELECT record_count FROM metric_snapshots WHERE flow_id = ? AND window_start = ? LIMIT 1",
            (int(flow_id), str(window_start)),
        )
        row = cursor.fetchone()
        return int(row[0]) if row is not None else None

    def purge_older_than(self, window_start: str) -> int:
        """Delete snapshots older than ``window_start`` (date string); returns rows removed."""
        cursor = self._conn.execute(
            "DELETE FROM metric_snapshots WHERE window_start < ?", (str(window_start),)
        )
        self._conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        self._conn.close()
