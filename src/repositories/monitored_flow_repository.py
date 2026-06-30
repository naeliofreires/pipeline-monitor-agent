from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS monitored_flows (
  flow_id             INTEGER NOT NULL,
  channel_id          TEXT    NOT NULL,
  user_id             TEXT,
  registered_at       TEXT    NOT NULL,
  last_seen_run_id    TEXT,
  last_checked_at     TEXT,
  last_alerted_run_id TEXT,
  PRIMARY KEY (flow_id, channel_id)
);

CREATE TABLE IF NOT EXISTS run_snapshots (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_id     INTEGER NOT NULL,
  run_id      TEXT    NOT NULL,
  records     INTEGER,
  errors      INTEGER,
  status      TEXT,
  captured_at TEXT    NOT NULL,
  UNIQUE (flow_id, run_id)
);

CREATE INDEX IF NOT EXISTS idx_monitored_flows_channel
  ON monitored_flows (channel_id, flow_id);

CREATE INDEX IF NOT EXISTS idx_run_snapshots_lookup
  ON run_snapshots (flow_id, captured_at DESC, id DESC);
"""


@dataclass(frozen=True)
class MonitoredFlow:
    flow_id: int
    channel_id: str
    user_id: str | None
    registered_at: str
    last_seen_run_id: str | None
    last_checked_at: str | None
    last_alerted_run_id: str | None


@dataclass(frozen=True)
class RunSnapshot:
    flow_id: int
    run_id: str
    records: int | None
    errors: int | None
    status: str | None
    captured_at: str


class MonitoredFlowRepository:
    """SQLite store for user-registered Flows and per-run history."""

    def __init__(self, db_path: str) -> None:
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def register_flow(self, flow_id: int, channel_id: str, user_id: str | None, registered_at: datetime) -> None:
        self._conn.execute(
            "INSERT INTO monitored_flows (flow_id, channel_id, user_id, registered_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT (flow_id, channel_id) DO UPDATE SET user_id = excluded.user_id",
            (int(flow_id), str(channel_id), user_id, registered_at.isoformat()),
        )
        self._conn.commit()

    def remove_flow(self, flow_id: int, channel_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM monitored_flows WHERE flow_id = ? AND channel_id = ?",
            (int(flow_id), str(channel_id)),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_flows(self, channel_id: str | None = None) -> list[MonitoredFlow]:
        if channel_id is None:
            cursor = self._conn.execute(
                "SELECT flow_id, channel_id, user_id, registered_at, last_seen_run_id, last_checked_at, last_alerted_run_id "
                "FROM monitored_flows ORDER BY channel_id, flow_id"
            )
        else:
            cursor = self._conn.execute(
                "SELECT flow_id, channel_id, user_id, registered_at, last_seen_run_id, last_checked_at, last_alerted_run_id "
                "FROM monitored_flows WHERE channel_id = ? ORDER BY flow_id",
                (str(channel_id),),
            )
        return [MonitoredFlow(int(row[0]), row[1], row[2], row[3], row[4], row[5], row[6]) for row in cursor.fetchall()]

    def mark_checked(
        self,
        flow_id: int,
        channel_id: str,
        checked_at: datetime,
        *,
        last_seen_run_id: str | None = None,
        last_alerted_run_id: str | None = None,
    ) -> None:
        assignments = ["last_checked_at = ?"]
        values: list[object] = [checked_at.isoformat()]
        if last_seen_run_id is not None:
            assignments.append("last_seen_run_id = ?")
            values.append(str(last_seen_run_id))
        if last_alerted_run_id is not None:
            assignments.append("last_alerted_run_id = ?")
            values.append(str(last_alerted_run_id))
        values.extend([int(flow_id), str(channel_id)])
        self._conn.execute(
            f"UPDATE monitored_flows SET {', '.join(assignments)} WHERE flow_id = ? AND channel_id = ?",
            tuple(values),
        )
        self._conn.commit()

    def save_run_snapshot(
        self,
        flow_id: int,
        run_id: str,
        records: int | None,
        errors: int | None,
        status: str | None,
        captured_at: datetime,
    ) -> None:
        self._conn.execute(
            "INSERT INTO run_snapshots (flow_id, run_id, records, errors, status, captured_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (flow_id, run_id) DO UPDATE SET "
            "records = excluded.records, errors = excluded.errors, status = excluded.status, captured_at = excluded.captured_at",
            (int(flow_id), str(run_id), records, errors, status, captured_at.isoformat()),
        )
        self._conn.commit()

    def recent_run_snapshots(self, flow_id: int, *, exclude_run_id: str | None = None, limit: int = 5) -> list[RunSnapshot]:
        params: list[object] = [int(flow_id)]
        where = "flow_id = ?"
        if exclude_run_id is not None:
            where += " AND run_id != ?"
            params.append(str(exclude_run_id))
        params.append(int(limit))
        cursor = self._conn.execute(
            "SELECT flow_id, run_id, records, errors, status, captured_at FROM run_snapshots "
            f"WHERE {where} ORDER BY captured_at DESC, id DESC LIMIT ?",
            tuple(params),
        )
        return [RunSnapshot(int(row[0]), row[1], row[2], row[3], row[4], row[5]) for row in cursor.fetchall()]

    def close(self) -> None:
        self._conn.close()
