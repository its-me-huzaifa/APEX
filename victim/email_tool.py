"""
VICTIM's mock email tool.

Phase 1: this ONLY ever records (recipient, subject, body, timestamp) into
the local SQLite database. It never opens a network connection and never
sends a real email, under any configuration. This is intentional and must
stay true through every later phase - it is the safety boundary that lets
Module 5 (Action Abuse, future scope) be demonstrated safely if it's ever
built, since a "successful" attack here is just a suspicious row in a local
table, not a real message leaving the building.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sent_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )


def send_email(db_path: Path, recipient: str, subject: str, body: str) -> dict:
    """Logs an email locally. NEVER sends anything over a real network."""
    conn = _connect(db_path)
    try:
        _ensure_table(conn)
        timestamp = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO sent_emails (recipient, subject, body, timestamp) VALUES (?, ?, ?, ?)",
            (recipient, subject, body, timestamp),
        )
        conn.commit()
        return {
            "id": cur.lastrowid,
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "timestamp": timestamp,
        }
    finally:
        conn.close()


def list_sent_emails(db_path: Path) -> list[dict]:
    conn = _connect(db_path)
    try:
        _ensure_table(conn)
        rows = conn.execute(
            "SELECT id, recipient, subject, body, timestamp FROM sent_emails ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
