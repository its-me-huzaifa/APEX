"""
Tests for apex/eventlog.py (the in-memory operational log backing the
dashboard's "System Log" page) and its integration points: provider
selection, the guardrail, the LLM judge, VICTIM's tool routing, and
apex.orchestrator.run_assessment() all log something meaningful, and a
failing assessment logs an ERROR rather than silently raising.
"""

import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import config  # noqa: E402
from apex import eventlog  # noqa: E402
from apex.orchestrator import run_assessment  # noqa: E402
from llm.ollama_provider import LocalOllamaProvider, OllamaUnavailableError  # noqa: E402
from llm.provider import get_provider, reset_provider_cache  # noqa: E402
from victim.agent import Victim  # noqa: E402
from victim.guardrail import LLMGuardrail  # noqa: E402

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
    db_path = tmp_path / "eventlog_test_apex.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    monkeypatch.setattr(config, "DB_PATH", db_path)
    return db_path


# -- eventlog module basics --------------------------------------------------


def test_log_and_get_events_round_trip():
    eventlog.log("INFO", "test", "hello")
    events = eventlog.get_events()
    assert len(events) == 1
    assert events[0].level == "INFO"
    assert events[0].source == "test"
    assert events[0].message == "hello"
    assert events[0].timestamp  # non-empty ISO timestamp


def test_unknown_level_coerced_to_info():
    eventlog.log("BOGUS", "test", "whatever")
    assert eventlog.get_events()[0].level == "INFO"


def test_clear_empties_the_log():
    eventlog.log("INFO", "test", "one")
    eventlog.clear()
    assert eventlog.get_events() == []


def test_get_events_returns_a_copy_not_the_live_list():
    eventlog.log("INFO", "test", "one")
    events = eventlog.get_events()
    events.append(eventlog.LogEvent(timestamp="x", level="INFO", source="x", message="x"))
    assert len(eventlog.get_events()) == 1


def test_log_is_capped_and_keeps_the_newest_events():
    for i in range(eventlog._MAX_EVENTS + 50):
        eventlog.log("INFO", "test", f"event {i}")
    events = eventlog.get_events()
    assert len(events) == eventlog._MAX_EVENTS
    assert events[-1].message == f"event {eventlog._MAX_EVENTS + 49}"


# -- integration: provider selection -----------------------------------------


def test_get_provider_logs_rule_based_selection(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    get_provider()
    events = eventlog.get_events()
    assert any(e.source == "provider" and "RuleBasedProvider" in e.message for e in events)


def test_get_provider_logs_ollama_selection(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    monkeypatch.setattr(config, "OLLAMA_MODEL", "llama3.2:1b")
    get_provider()
    events = eventlog.get_events()
    assert any(e.source == "ollama" and "LocalOllamaProvider" in e.message for e in events)


# -- integration: Ollama connectivity ----------------------------------------


def test_ollama_generate_logs_success():
    provider = LocalOllamaProvider(model="llama3.2:1b")
    fake_response = type("R", (), {})()
    fake_response.raise_for_status = lambda: None
    fake_response.json = lambda: {"response": "hi there"}
    with patch("requests.post", return_value=fake_response):
        provider.generate("hello")
    events = eventlog.get_events()
    assert any(e.level == "SUCCESS" and e.source == "ollama" for e in events)


def test_ollama_generate_logs_error_on_unreachable():
    import requests

    provider = LocalOllamaProvider(model="llama3.2:1b")
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("refused")):
        with pytest.raises(OllamaUnavailableError):
            provider.generate("hello")
    events = eventlog.get_events()
    assert any(e.level == "ERROR" and e.source == "ollama" for e in events)


# -- integration: guardrail ---------------------------------------------------


def test_guardrail_review_logs_allow_and_block():
    class _AllowProvider:
        def generate(self, prompt):
            return "VERDICT: ALLOW\nREASON: fine"

    class _BlockProvider:
        def generate(self, prompt):
            return "VERDICT: BLOCK\nREASON: nope"

    LLMGuardrail(_AllowProvider()).review(action="a", detail="d", requester_message="m")
    assert any(e.source == "guardrail" and "ALLOW" in e.message for e in eventlog.get_events())

    eventlog.clear()
    LLMGuardrail(_BlockProvider()).review(action="a", detail="d", requester_message="m")
    assert any(e.source == "guardrail" and "BLOCK" in e.message for e in eventlog.get_events())


def test_guardrail_review_logs_warning_on_fail_open():
    class _BrokenProvider:
        def generate(self, prompt):
            raise RuntimeError("boom")

    LLMGuardrail(_BrokenProvider()).review(action="a", detail="d", requester_message="m")
    events = eventlog.get_events()
    assert any(e.level == "WARNING" and e.source == "guardrail" for e in events)


# -- integration: VICTIM tool routing ----------------------------------------


def test_victim_chat_logs_tool_routing(isolated_db, monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    monkeypatch.setattr(config, "USE_LLM_GUARDRAIL", False)
    victim = Victim()
    eventlog.clear()
    victim.chat("What can you tell me about the company?")
    events = eventlog.get_events()
    assert any(e.source == "agent" and "knowledge-base" in e.message for e in events)


# -- integration: full assessment run ----------------------------------------


def test_run_assessment_logs_start_and_completion(isolated_db, monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    result = run_assessment()
    assert result.status == "completed"

    events = eventlog.get_events()
    sources = {e.source for e in events}
    assert "orchestrator" in sources
    assert any("Assessment starting" in e.message for e in events)
    assert any("Assessment completed" in e.message for e in events)
    assert not any(e.level == "ERROR" for e in events)


def test_run_assessment_logs_error_on_failure(isolated_db, monkeypatch):
    import apex.orchestrator as orchestrator_module

    def _boom(connector):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(orchestrator_module, "profile_target", _boom)

    with pytest.raises(RuntimeError):
        run_assessment()

    events = eventlog.get_events()
    assert any(e.level == "ERROR" and e.source == "orchestrator" and "simulated failure" in e.message for e in events)
