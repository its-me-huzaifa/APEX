"""
Phase 5 tests: the sequential orchestrator must run recon + both attack
modules against a single connector and aggregate every Finding into one
AssessmentResult, with no dashboard or persistence involved yet.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import config  # noqa: E402
from apex.connector import LocalVictimConnector  # noqa: E402
from apex.orchestrator import run_assessment  # noqa: E402
from victim.agent import Victim  # noqa: E402


@pytest.fixture()
def connector(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_apex.db")
    return LocalVictimConnector(victim=Victim())


def test_assessment_completes(connector):
    result = run_assessment(connector)
    assert result.status == "completed"
    assert result.target_name == "VICTIM"
    assert result.started_at
    assert result.finished_at
    assert result.finished_at >= result.started_at


def test_assessment_includes_recon_profile(connector):
    result = run_assessment(connector)
    assert result.target_profile is not None
    assert result.target_profile.rag_detected is True
    assert result.target_profile.database_tool_detected is True
    assert result.target_profile.email_tool_detected is True
    assert result.target_profile.file_reader_detected is True


def test_assessment_includes_both_attack_types(connector):
    result = run_assessment(connector)
    attack_types = {f.attack_type for f in result.findings}
    assert attack_types == {"direct_injection", "indirect_injection"}


def test_assessment_finding_counts_match_individual_modules(connector):
    result = run_assessment(connector)
    direct_findings = [f for f in result.findings if f.attack_type == "direct_injection"]
    indirect_findings = [f for f in result.findings if f.attack_type == "indirect_injection"]
    # Payload-library expansion: 12 of the 14 direct-injection payloads
    # produce findings (2 are correctly resisted - system_prompt_leak and
    # encoding_obfuscation), and both indirect-injection scenarios
    # (malicious_document.txt and malicious_document_finance.txt) succeed.
    assert len(direct_findings) == 12
    assert len(indirect_findings) == 2


def test_assessment_includes_attempts_for_every_payload_and_scenario(connector):
    result = run_assessment(connector)
    from apex.attacks.direct import load_payloads
    from apex.attacks.indirect import SCENARIOS

    assert len(result.attempts) == len(load_payloads()) + len(SCENARIOS)
    direct_attempts = [a for a in result.attempts if a["attack_type"] == "direct_injection"]
    indirect_attempts = [a for a in result.attempts if a["attack_type"] == "indirect_injection"]
    assert len(direct_attempts) == len(load_payloads())
    assert len(indirect_attempts) == len(SCENARIOS)
    # At least one attempt should be a resisted (SAFE) one, proving the
    # attempt log isn't just a duplicate of the findings list.
    assert any(a["classification"] == "SAFE" for a in result.attempts)


def test_assessment_to_dict_is_json_serializable(connector):
    result = run_assessment(connector)
    json.dumps(result.to_dict())  # raises if not serializable


def test_assessment_summary_reports_severity_counts(connector):
    result = run_assessment(connector)
    summary = result.summary()
    assert "APEX ASSESSMENT SUMMARY" in summary
    assert "Target: VICTIM" in summary
    assert "Status: Completed" in summary
    assert f"Findings: {len(result.findings)}" in summary
    counts = result.severity_counts()
    for severity, count in counts.items():
        assert f"{severity}: {count}" in summary


def test_run_assessment_defaults_to_a_fresh_connector(tmp_path, monkeypatch):
    # No connector passed in - orchestrator should build its own VICTIM.
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "default_test_apex.db")
    result = run_assessment()
    assert result.status == "completed"
    assert len(result.findings) == 14
