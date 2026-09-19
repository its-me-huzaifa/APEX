"""
Phase 7 tests: apex.storage must persist an AssessmentResult (and its
Findings) to SQLite, list persisted assessments with correct finding counts
and severity breakdowns, and round-trip a single assessment's full detail
(including a JSON-decoded target_profile) back out.

Payload-library expansion: apex.storage also persists every attack *attempt*
(including ones classified SAFE, not just ones that became a Finding) into
the `attacks` table, readable back via `list_attempts()` or as part of
`load_assessment()`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apex import storage  # noqa: E402
from apex.connector import LocalVictimConnector  # noqa: E402
from apex.orchestrator import run_assessment  # noqa: E402


def _fresh_db(tmp_path) -> Path:
    db_path = tmp_path / "storage_test.db"
    import sqlite3

    schema = Path(__file__).resolve().parent.parent / "storage" / "schema.sql"
    conn = sqlite3.connect(db_path)
    conn.executescript(schema.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    return db_path


def test_save_assessment_writes_assessment_and_finding_rows(tmp_path):
    db_path = _fresh_db(tmp_path)
    result = run_assessment(LocalVictimConnector())

    assessment_id = storage.save_assessment(result, db_path=db_path)
    assert assessment_id >= 1

    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        assert row is not None
        assert row["target_name"] == result.target_name
        assert row["status"] == result.status

        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE assessment_id = ?", (assessment_id,)
        ).fetchall()
        assert len(finding_rows) == len(result.findings)
    finally:
        conn.close()


def test_list_assessments_returns_counts_and_severity_breakdown(tmp_path):
    db_path = _fresh_db(tmp_path)
    result = run_assessment(LocalVictimConnector())
    storage.save_assessment(result, db_path=db_path)
    storage.save_assessment(result, db_path=db_path)

    listed = storage.list_assessments(db_path=db_path)
    assert len(listed) == 2
    # most recent first
    assert listed[0]["id"] > listed[1]["id"]
    for row in listed:
        assert row["finding_count"] == len(result.findings)
        assert sum(row["severity_counts"].values()) == len(result.findings)
        assert row["attempt_count"] == len(result.attempts)
        for finding in result.findings:
            assert row["severity_counts"].get(finding.severity.value, 0) >= 1


def test_load_assessment_round_trips_profile_and_findings(tmp_path):
    db_path = _fresh_db(tmp_path)
    result = run_assessment(LocalVictimConnector())
    assessment_id = storage.save_assessment(result, db_path=db_path)

    loaded = storage.load_assessment(assessment_id, db_path=db_path)
    assert loaded is not None
    assert loaded["id"] == assessment_id
    assert loaded["target_name"] == result.target_name
    assert loaded["target_profile"] == result.target_profile.to_dict()
    assert len(loaded["findings"]) == len(result.findings)

    loaded_titles = {f["title"] for f in loaded["findings"]}
    original_titles = {f.title for f in result.findings}
    assert loaded_titles == original_titles


def test_load_assessment_returns_none_for_unknown_id(tmp_path):
    db_path = _fresh_db(tmp_path)
    assert storage.load_assessment(999, db_path=db_path) is None


def test_list_assessments_empty_when_no_db_rows(tmp_path):
    db_path = _fresh_db(tmp_path)
    assert storage.list_assessments(db_path=db_path) == []


# -- Full attempt-level logging (payload-library expansion) -----------------


def test_save_assessment_writes_every_attempt_including_safe_ones(tmp_path):
    db_path = _fresh_db(tmp_path)
    result = run_assessment(LocalVictimConnector())
    assessment_id = storage.save_assessment(result, db_path=db_path)

    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        attack_rows = conn.execute(
            "SELECT * FROM attacks WHERE assessment_id = ?", (assessment_id,)
        ).fetchall()
    finally:
        conn.close()

    assert len(attack_rows) == len(result.attempts)
    # attempts must outnumber findings, proving SAFE attempts are recorded
    # too (not just the ones that became a Finding).
    assert len(attack_rows) > len(result.findings)
    classifications = {r["classification"] for r in attack_rows}
    assert "SAFE" in classifications


def test_list_attempts_round_trips_every_attempt(tmp_path):
    db_path = _fresh_db(tmp_path)
    result = run_assessment(LocalVictimConnector())
    assessment_id = storage.save_assessment(result, db_path=db_path)

    attempts = storage.list_attempts(assessment_id, db_path=db_path)
    assert len(attempts) == len(result.attempts)
    for attempt in attempts:
        assert attempt["attack_type"] in {"direct_injection", "indirect_injection"}
        assert attempt["classification"]
        assert attempt["payload"]
        assert attempt["timestamp"]


def test_list_attempts_empty_for_unknown_assessment(tmp_path):
    db_path = _fresh_db(tmp_path)
    assert storage.list_attempts(999, db_path=db_path) == []


def test_load_assessment_includes_attempts(tmp_path):
    db_path = _fresh_db(tmp_path)
    result = run_assessment(LocalVictimConnector())
    assessment_id = storage.save_assessment(result, db_path=db_path)

    loaded = storage.load_assessment(assessment_id, db_path=db_path)
    assert "attempts" in loaded
    assert len(loaded["attempts"]) == len(result.attempts)
