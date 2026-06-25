"""SQLite persistence for dashboard alerts and campaigns."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

from guardian.security.vault import data_dir

_MAX_ALERTS = 500
_MAX_CAMPAIGNS = 100
_lock = threading.Lock()
_initialized = False


def _db_path() -> str:
    path = data_dir() / "dashboard.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    global _initialized
    with _lock:
        if _initialized:
            return
        with _connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    ts REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    last_seen REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_seen ON campaigns(last_seen DESC)")
        _initialized = True


def save_alert(alert: dict[str, Any]) -> None:
    init_db()
    ts = float(alert.get("timestamp") or time.time())
    payload = json.dumps(alert, default=str)
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO alerts (id, data, ts) VALUES (?, ?, ?)",
                (alert["id"], payload, ts),
            )
            conn.execute(
                """
                DELETE FROM alerts WHERE id NOT IN (
                    SELECT id FROM alerts ORDER BY ts DESC LIMIT ?
                )
                """,
                (_MAX_ALERTS,),
            )


def save_campaign(campaign: dict[str, Any]) -> None:
    init_db()
    last_seen = float(campaign.get("last_seen") or time.time())
    payload = json.dumps(campaign, default=str)
    with _lock:
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO campaigns (id, data, last_seen) VALUES (?, ?, ?)",
                (campaign["id"], payload, last_seen),
            )
            conn.execute(
                """
                DELETE FROM campaigns WHERE id NOT IN (
                    SELECT id FROM campaigns ORDER BY last_seen DESC LIMIT ?
                )
                """,
                (_MAX_CAMPAIGNS,),
            )


def load_alerts(limit: int = _MAX_ALERTS) -> list[dict[str, Any]]:
    init_db()
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT data FROM alerts ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
    out: list[dict[str, Any]] = []
    for (raw,) in reversed(rows):
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


def load_campaigns() -> list[dict[str, Any]]:
    init_db()
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT data FROM campaigns ORDER BY last_seen DESC LIMIT ?",
                (_MAX_CAMPAIGNS,),
            ).fetchall()
    out: list[dict[str, Any]] = []
    for (raw,) in rows:
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


def export_snapshot(alerts: list[dict], campaigns: list[dict], stats: dict) -> dict[str, Any]:
    return {
        "exported_at": time.time(),
        "exported_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stats": stats,
        "alerts": alerts,
        "campaigns": campaigns,
    }
