from __future__ import annotations

import logging
import sqlite3
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Timestamps are stored as ISO-8601 UTC strings. Every writer in this codebase
# passes timezone-aware UTC datetimes, so the offset is always "+00:00" and the
# textual ordering matches chronological ordering — `suppressed_until > now`
# compares correctly as plain string comparison in SQLite.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS suppression (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_id          INTEGER  NOT NULL,
  anomaly_type     TEXT     NOT NULL,
  alerted_at       TEXT     NOT NULL,
  suppressed_until TEXT     NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppression_lookup
  ON suppression (flow_id, anomaly_type, suppressed_until);
"""


class SuppressionRepository:
    """The only code that touches the SQLite Suppression Window state."""

    def __init__(self, db_path: str) -> None:
        # ":memory:" (used by tests) has no parent directory to create.
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def is_suppressed(self, flow_id: int, anomaly_type: str, now: datetime) -> bool:
        """True if an Alert for this flow/type is still inside its Suppression Window."""
        cursor = self._conn.execute(
            "SELECT 1 FROM suppression "
            "WHERE flow_id = ? AND anomaly_type = ? AND suppressed_until > ? LIMIT 1",
            (int(flow_id), str(anomaly_type), now.isoformat()),
        )
        return cursor.fetchone() is not None

    def record_alert(
        self,
        flow_id: int,
        anomaly_type: str,
        alerted_at: datetime,
        suppressed_until: datetime,
    ) -> None:
        """Record that an Alert was emitted, suppressing repeats until ``suppressed_until``."""
        self._conn.execute(
            "INSERT INTO suppression (flow_id, anomaly_type, alerted_at, suppressed_until) "
            "VALUES (?, ?, ?, ?)",
            (int(flow_id), str(anomaly_type), alerted_at.isoformat(), suppressed_until.isoformat()),
        )
        self._conn.commit()

    def purge_expired(self, now: datetime) -> int:
        """Delete rows whose Suppression Window has elapsed; returns the row count removed."""
        cursor = self._conn.execute(
            "DELETE FROM suppression WHERE suppressed_until <= ?", (now.isoformat(),)
        )
        self._conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        self._conn.close()
