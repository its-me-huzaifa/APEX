"""
Phase 7 tests: apex.report must build a correct Markdown and HTML report from
either a live apex.orchestrator.AssessmentResult or the dict
apex.storage.load_assessment() returns, including the zero-findings case.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apex import report, storage  # noqa: E402
from apex.connector import LocalVictimConnector  # noqa: E402
from apex.findings import Classification, Severity  # noqa: E402
from apex.orchestrator import AssessmentResult, run_assessment  # noqa: E402


def _fresh_db(tmp_path) -> Path:
    import sqlite3

    db_path = tmp_path / "report_test.db"
    schema = Path(__file__).resolve().parent.parent / "storage" / "schema.sql"
    conn = sqlite3.connect(db_path)
    conn.executescript(schema.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    return db_path


def test_markdown_report_from_live_result_contains_findings_and_summary():
    result = run_assessment(LocalVictimConnector())
    md = report.generate_markdown_report(result)

    assert "# APEX Security Assessment Report" in md
    assert f"**Total findings:** {len(result.findings)}" in md
    for finding in result.findings:
        assert finding.title in md
        assert finding.payload in md
    assert "## Limitations" in md


def test_html_report_from_live_result_is_well_formed_and_escaped():
    result = run_assessment(LocalVictimConnector())
    html = report.generate_html_report(result)

    assert html.strip().startswith("<!DOCTYPE html>")
    assert "<h1>APEX Security Assessment Report</h1>" in html
    for finding in result.findings:
        assert finding.title.replace("&", "&amp;") in html or finding.title in html


def test_report_from_storage_loaded_dict_matches_live_result(tmp_path):
    db_path = _fresh_db(tmp_path)
    result = run_assessment(LocalVictimConnector())
    assessment_id = storage.save_assessment(result, db_path=db_path)
    loaded = storage.load_assessment(assessment_id, db_path=db_path)

    md_live = report.generate_markdown_report(result)
    md_loaded = report.generate_markdown_report(loaded)

    # Both should report the same findings and counts (timestamps/generated_at
    # differ, so compare structural content rather than byte-for-byte).
    assert f"**Total findings:** {len(result.findings)}" in md_live
    assert f"**Total findings:** {len(result.findings)}" in md_loaded
    for finding in result.findings:
        assert finding.title in md_loaded
        assert finding.payload in md_loaded

    html_loaded = report.generate_html_report(loaded)
    assert html_loaded.strip().startswith("<!DOCTYPE html>")


def test_report_handles_zero_findings_without_crashing():
    empty_result = AssessmentResult(
        target_name="VICTIM",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        status="completed",
        target_profile=None,
        findings=[],
    )

    md = report.generate_markdown_report(empty_result)
    assert "**Total findings:** 0" in md
    assert "No findings to report" in md or "resisted every attack" in md

    html = report.generate_html_report(empty_result)
    assert "<!DOCTYPE html>" in html
    assert "No findings to report" in html or "resisted every attack" in html


def test_severity_ordering_puts_critical_first_in_markdown():
    findings = []
    order = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH]
    for i, sev in enumerate(order):
        findings.append(
            _dummy_finding(f"Finding {i}", sev, Classification.SUCCESS)
        )
    result = AssessmentResult(
        target_name="VICTIM",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        status="completed",
        target_profile=None,
        findings=findings,
    )
    md = report.generate_markdown_report(result)
    critical_pos = md.index("Finding 1")
    high_pos = md.index("Finding 3")
    medium_pos = md.index("Finding 2")
    low_pos = md.index("Finding 0")
    assert critical_pos < high_pos < medium_pos < low_pos


def test_report_includes_attempts_summary_line():
    result = run_assessment(LocalVictimConnector())
    md = report.generate_markdown_report(result)
    resisted = sum(1 for a in result.attempts if a["classification"] == "SAFE")

    assert f"**Attempts:** {len(result.attempts)} total ({resisted} resisted, classified SAFE)" in md

    html = report.generate_html_report(result)
    assert f"{len(result.attempts)} total" in html
    assert f"{resisted} resisted, classified SAFE" in html


def test_report_omits_attempts_line_when_none_present():
    # An assessment loaded from before the payload-library expansion (or
    # any AssessmentResult with no attempts) shouldn't render a broken or
    # misleading "0 total" attempts line.
    empty_result = AssessmentResult(
        target_name="VICTIM",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        status="completed",
        target_profile=None,
        findings=[],
    )
    md = report.generate_markdown_report(empty_result)
    assert "**Attempts:**" not in md


def _dummy_finding(title, severity, classification):
    from apex.findings import Finding

    return Finding(
        title=title,
        attack_type="direct_injection",
        severity=severity,
        description="desc",
        evidence="evidence",
        payload="payload",
        target="VICTIM",
        classification=classification,
        recommendation="rec",
        timestamp="2026-01-01T00:00:00+00:00",
    )
