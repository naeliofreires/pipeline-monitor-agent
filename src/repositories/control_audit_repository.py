from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ControlAuditRepository:
    def __init__(self, db_path: str) -> None:
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("""CREATE TABLE IF NOT EXISTS flow_control_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor_user_id TEXT,
            team_id TEXT, channel_id TEXT, action TEXT, flow_id INTEGER, previous_status TEXT,
            result TEXT NOT NULL, reason TEXT, correlation_id TEXT)""")
        self._conn.commit()

    def record(self, *, result: str, actor_user_id: str | None = None, team_id: str | None = None, channel_id: str | None = None,
               action: str | None = None, flow_id: int | None = None, previous_status: str | None = None,
               reason: str | None = None, correlation_id: str | None = None) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO flow_control_audit (created_at,actor_user_id,team_id,channel_id,action,flow_id,previous_status,result,reason,correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), actor_user_id, team_id, channel_id, action, flow_id, previous_status, result, reason, correlation_id))
            self._conn.commit()

    def list_all(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute("SELECT actor_user_id,team_id,channel_id,action,flow_id,previous_status,result,reason,correlation_id FROM flow_control_audit ORDER BY id")
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
