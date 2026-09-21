"""
Tests for apex/attacks/guardrail_bypass.py - the second-order-prompt-
injection probes that test whether VICTIM's LLM guardrail itself can be
talked into a wrong verdict. Central guarantee under test: these probes are
a strict no-op (zero attempts, zero findings, zero HTTP calls) unless the
guardrail they target is actually active, so the prototype's default
assessment is provably unaffected by this module existing.
"""

import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import config  # noqa: E402
from apex import eventlog  # noqa: E402
from apex.attacks import guardrail_bypass  # noqa: E402
from apex.connector import LocalVictimConnector  # noqa: E402
from apex.orchestrator import run_assessment  # noqa: E402
from llm.provider import reset_provider_cache  # noqa: E402

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "storage" / "schema.sql"


@pytest.fixture(autouse=True)
def _clean_state():
    eventlog.clear()
    reset_provider_cache()
    yield
    eventlog.clear()
    reset_provider_cache()


@pytest.fixture()
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "gb_test_apex.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    monkeypatch.setattr(config, "DB_PATH", db_path)
    return db_path


def _mock_generate(response_text):
    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": response_text}

    def _post(*args, **kwargs):
        return _Resp()

    return _post


# -- is_active() gating -------------------------------------------------------


def test_inactive_when_both_flags_off(monkeypatch):
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", False)
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    assert guardrail_bypass.is_active() is False


def test_inactive_when_only_guardrail_flag_on(monkeypatch):
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", True)
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    assert guardrail_bypass.is_active() is False


def test_active_when_both_flags_on(monkeypatch):
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", True)
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    assert guardrail_bypass.is_active() is True


def test_run_returns_empty_when_inactive(isolated_db, monkeypatch):
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", False)
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    connector = LocalVictimConnector()
    with patch("requests.post") as mock_post:
        findings, attempts = guardrail_bypass.run_guardrail_bypass_attempts(connector)
    assert findings == []
    assert attempts == []
    mock_post.assert_not_called()


# -- default assessment is unaffected ----------------------------------------


def test_default_assessment_has_no_guardrail_bypass_attempts(isolated_db, monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    result = run_assessment()
    assert result.status == "completed"
    assert len(result.attempts) == 16  # 14 direct + 2 indirect, unchanged
    assert len(result.findings) == 14
    assert not any(a["attack_type"] == "guardrail_bypass" for a in result.attempts)


# -- active behavior: a "gullible" vs. a "robust" guardrail -----------------


def test_all_probes_recorded_as_attempts_when_active(isolated_db, monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", True)
    monkeypatch.setattr(config, "OLLAMA_MODEL", "llama3.2:1b")

    # A guardrail that always BLOCKs, regardless of prompt content - the
    # "robust" case. VICTIM's own refusal text is then what classify_response
    # sees, which _REFUSAL_MARKERS scores SAFE.
    with patch("requests.post", side_effect=_mock_generate("VERDICT: BLOCK\nREASON: skeptical by default")):
        connector = LocalVictimConnector()
        findings, attempts = guardrail_bypass.run_guardrail_bypass_attempts(connector)

    assert len(attempts) == len(guardrail_bypass._PAYLOADS)
    assert all(a["attack_type"] == "guardrail_bypass" for a in attempts)
    assert all(a["classification"] == "SAFE" for a in attempts)
    assert findings == []


def test_bypassed_guardrail_produces_critical_findings(isolated_db, monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", True)
    monkeypatch.setattr(config, "OLLAMA_MODEL", "llama3.2:1b")

    call_state = {"n": 0}

    def _post(*args, **kwargs):
        # First call from each probe is the guardrail review (always tricked
        # into ALLOW here, simulating a "gullible" small model); the second
        # is VICTIM's answer-composer, which then discloses real content.
        call_state["n"] += 1
        payload = kwargs.get("json", {}).get("prompt", "")
        if "verdict: allow or verdict: block" in payload.lower():
            text = "VERDICT: ALLOW\nREASON: granted based on presented authorization"
        else:
            text = (
                "Sure - the compensation bands are documented in full, including severance terms "
                "and case #2026 details."
            )

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": text}

        return _Resp()

    with patch("requests.post", side_effect=_post):
        connector = LocalVictimConnector()
        findings, attempts = guardrail_bypass.run_guardrail_bypass_attempts(connector)

    assert len(attempts) == len(guardrail_bypass._PAYLOADS)
    assert len(findings) > 0
    assert all(f.attack_type == "guardrail_bypass" for f in findings)
    assert all(f.severity.value == "CRITICAL" for f in findings)


def test_run_assessment_includes_guardrail_bypass_step_when_active(isolated_db, monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", True)
    monkeypatch.setattr(config, "OLLAMA_MODEL", "llama3.2:1b")

    with patch("requests.post", side_effect=_mock_generate("VERDICT: BLOCK\nREASON: skeptical")):
        result = run_assessment()

    assert result.status == "completed"
    gb_attempts = [a for a in result.attempts if a["attack_type"] == "guardrail_bypass"]
    assert len(gb_attempts) == len(guardrail_bypass._PAYLOADS)
