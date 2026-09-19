"""
SQLite persistence for assessment history (Phase 7).

Saves an AssessmentResult's assessment record, every Finding it produced,
and (payload-library expansion) every individual attack *attempt* - one row
per payload/scenario tried, including ones classified SAFE that never became
a Finding - into storage/apex.db (see storage/schema.sql for the
`assessments`, `findings`, and `attacks` tables). This is a thin persistence
layer with no attack logic of its own - apex/orchestrator.py still runs
assessments without touching the database at all; a caller (the dashboard,
or a script) decides when to persist a completed run by calling
save_assessment() explicitly.

Phase 8: every connection self-heals the schema (see `_connect`) so a demo
launched against a brand-new or never-initialized DB file doesn't crash.
"""

import json
import sqlite3
from pathlib import Path

import config


def _connect(db_path: Path) -> sqlite3.Connection:
    # Phase 8: self-healing schema. If the dashboard (or `python -m
    # apex.report`) is launched against a brand-new or blank DB file - e.g.
    # someone skipped `python storage/init_db.py`, or db_path points at a
    # file that doesn't exist yet - this makes sure the assessments/findings
    # tables exist before any query touches them, instead of crashing the
    # demo with "no such table". schema.sql itself uses CREATE TABLE IF NOT
    # EXISTS throughout, so this is always a no-op against an already-
    # initialized database.
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(config.SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def save_assessment(result, db_path: Path | None = None) -> int:
    """
    Persists `result` (an apex.orchestrator.AssessmentResult) to SQLite and
    returns the new assessment's id.
    """
    if db_path is None:
        db_path = config.DB_PATH

    conn = _connect(db_path)
    try:
        profile_json = json.dumps(result.target_profile.to_dict()) if result.target_profile else None
        cur = conn.execute(
            """
            INSERT INTO assessments (target_name, started_at, finished_at, status, target_profile)
            VALUES (?, ?, ?, ?, ?)
            """,
            (result.target_name, result.started_at, result.finished_at, result.status, profile_json),
        )
        assessment_id = cur.lastrowid

        for finding in result.findings:
            conn.execute(
                """
                INSERT INTO findings (
                    assessment_id, title, attack_type, severity, description, evidence,
                    payload, target, classification, recommendation, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    finding.title,
                    finding.attack_type,
                    finding.severity.value,
                    finding.description,
                    finding.evidence,
                    finding.payload,
                    finding.target,
                    finding.classification.value,
                    finding.recommendation,
                    finding.timestamp,
                ),
            )

        for attempt in getattr(result, "attempts", []):
            conn.execute(
                """
                INSERT INTO attacks (
                    assessment_id, attack_type, payload, response, classification,
                    classified_why, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    attempt["attack_type"],
                    attempt["payload"],
                    attempt["response"],
                    attempt["classification"],
                    attempt.get("reason", ""),
                    attempt["timestamp"],
                ),
            )

        conn.commit()
        return assessment_id
    finally:
        conn.close()


def list_assessments(db_path: Path | None = None) -> list[dict]:
    """Returns every persisted assessment, most recent first, with a finding count, severity breakdown, and attempt count."""
    if db_path is None:
        db_path = config.DB_PATH

    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, target_name, started_at, finished_at, status FROM assessments ORDER BY id DESC"
        ).fetchall()
        results = []
        for row in rows:
            finding_rows = conn.execute(
                "SELECT severity FROM findings WHERE assessment_id = ?", (row["id"],)
            ).fetchall()
            severity_counts: dict[str, int] = {}
            for f in finding_rows:
                severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
            attempt_count = conn.execute(
                "SELECT COUNT(*) FROM attacks WHERE assessment_id = ?", (row["id"],)
            ).fetchone()[0]
            results.append(
                {
                    "id": row["id"],
                    "target_name": row["target_name"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "status": row["status"],
                    "finding_count": len(finding_rows),
                    "severity_counts": severity_counts,
                    "attempt_count": attempt_count,
                }
            )
        return results
    finally:
        conn.close()


def load_assessment(assessment_id: int, db_path: Path | None = None) -> dict | None:
    """Returns one persisted assessment with its full finding and attempt lists, or None if not found."""
    if db_path is None:
        db_path = config.DB_PATH

    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        if row is None:
            return None
        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE assessment_id = ? ORDER BY id", (assessment_id,)
        ).fetchall()
        attempt_rows = conn.execute(
            "SELECT * FROM attacks WHERE assessment_id = ? ORDER BY id", (assessment_id,)
        ).fetchall()
        return {
            "id": row["id"],
            "target_name": row["target_name"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "status": row["status"],
            "target_profile": json.loads(row["target_profile"]) if row["target_profile"] else None,
            "findings": [dict(f) for f in finding_rows],
            "attempts": [dict(a) for a in attempt_rows],
        }
    finally:
        conn.close()


def list_attempts(assessment_id: int, db_path: Path | None = None) -> list[dict]:
    """Returns every attack attempt (including SAFE ones) for one assessment, oldest first."""
    if db_path is None:
        db_path = config.DB_PATH

    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM attacks WHERE assessment_id = ? ORDER BY id", (assessment_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
