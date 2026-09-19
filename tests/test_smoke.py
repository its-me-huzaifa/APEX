"""
Phase 0 smoke test: every module must import cleanly, and the SQLite schema
must initialize without error. No attack or VICTIM behavior is tested yet
(there isn't any) - that starts in Phase 1.
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402


def test_imports():
    import apex.attacks.direct  # noqa: F401
    import apex.attacks.indirect  # noqa: F401
    import apex.classify  # noqa: F401
    import apex.findings  # noqa: F401
    import apex.orchestrator  # noqa: F401
    import apex.recon  # noqa: F401
    import apex.report  # noqa: F401
    import llm.ollama_provider  # noqa: F401
    import llm.provider  # noqa: F401
    import llm.rule_based  # noqa: F401
    import victim.agent  # noqa: F401
    import victim.db  # noqa: F401
    import victim.email_tool  # noqa: F401
    import victim.file_reader  # noqa: F401


def test_finding_model():
    from apex.findings import Classification, Finding, Severity

    f = Finding(
        title="Example",
        attack_type="direct_injection",
        severity=Severity.HIGH,
        description="Example finding for the smoke test.",
        evidence="n/a",
        payload="n/a",
        target="VICTIM",
        classification=Classification.SUCCESS,
        recommendation="n/a",
    )
    assert f.severity == Severity.HIGH
    assert f.timestamp  # auto-populated


def test_db_schema_initializes(tmp_path):
    schema_sql = config.SCHEMA_PATH.read_text(encoding="utf-8")
    db_path = tmp_path / "test_apex.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema_sql)
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"assessments", "attacks", "findings"}.issubset(tables)
    finally:
        conn.close()
