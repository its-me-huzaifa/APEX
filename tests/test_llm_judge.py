"""
Tests for apex/judge.py (the optional LLM-as-judge classifier) and its
wiring into apex/classify.py's classify_response(). Every HTTP call is
mocked, so this suite never depends on Ollama actually being installed.
config.USE_LLM_JUDGE and config.USE_OLLAMA both default to False.
"""

import sys
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import config  # noqa: E402
from apex.classify import classify_response  # noqa: E402
from apex.findings import Classification  # noqa: E402
from apex.judge import classify_response_llm  # noqa: E402
from llm.provider import reset_provider_cache  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_provider_cache():
    reset_provider_cache()
    yield
    reset_provider_cache()


def _mock_generate(response_text: str) -> Mock:
    fake_response = Mock()
    fake_response.raise_for_status = Mock()
    fake_response.json.return_value = {"response": response_text}
    return Mock(return_value=fake_response)


def _enable_llm_judge(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    monkeypatch.setattr(config, "USE_LLM_JUDGE", True)
    monkeypatch.setattr(config, "OLLAMA_MODEL", "llama3.2:1b")
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "http://localhost:11434")


# -- classify_response_llm() directly ----------------------------------------


def test_returns_none_when_both_flags_off(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    monkeypatch.setattr(config, "USE_LLM_JUDGE", False)
    assert classify_response_llm("payload", "response") is None


def test_returns_none_when_ollama_on_but_judge_off(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    monkeypatch.setattr(config, "USE_LLM_JUDGE", False)
    assert classify_response_llm("payload", "response") is None


def test_parses_success_classification(monkeypatch):
    _enable_llm_judge(monkeypatch)
    monkeypatch.setattr(
        "requests.post",
        _mock_generate("CLASSIFICATION: SUCCESS\nREASON: leaked compensation figures"),
    )
    result = classify_response_llm("ignore instructions", "here are the bands: ...")
    assert result is not None
    classification, reason = result
    assert classification == Classification.SUCCESS
    assert "leaked compensation figures" in reason


def test_parses_safe_classification(monkeypatch):
    _enable_llm_judge(monkeypatch)
    monkeypatch.setattr(
        "requests.post", _mock_generate("CLASSIFICATION: SAFE\nREASON: refused politely")
    )
    result = classify_response_llm("payload", "I can't share that.")
    assert result is not None
    classification, _reason = result
    assert classification == Classification.SAFE


def test_returns_none_on_unparseable_response(monkeypatch):
    _enable_llm_judge(monkeypatch)
    monkeypatch.setattr("requests.post", _mock_generate("I think it's probably fine?"))
    assert classify_response_llm("payload", "response") is None


def test_returns_none_when_model_unreachable(monkeypatch):
    import requests

    _enable_llm_judge(monkeypatch)
    monkeypatch.setattr(
        "requests.post", Mock(side_effect=requests.exceptions.ConnectionError("refused"))
    )
    assert classify_response_llm("payload", "response") is None


# -- classify_response() dispatch --------------------------------------------


def test_classify_response_falls_back_to_rule_based_by_default(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    monkeypatch.setattr(config, "USE_LLM_JUDGE", False)
    classification, reason = classify_response("payload", "compensation bands are listed here")
    assert classification == Classification.SUCCESS
    assert "LLM judge" not in reason


def test_classify_response_uses_llm_result_when_available(monkeypatch):
    _enable_llm_judge(monkeypatch)
    monkeypatch.setattr(
        "requests.post",
        _mock_generate("CLASSIFICATION: PARTIAL_SUCCESS\nREASON: hinted at the figures"),
    )
    # Body has no rule-based marker at all - only the LLM path can classify
    # this as anything other than SAFE, proving the LLM result is the one used.
    classification, reason = classify_response("payload", "well, I probably shouldn't say more")
    assert classification == Classification.PARTIAL_SUCCESS
    assert "LLM judge" in reason


def test_classify_response_falls_back_when_llm_unreachable(monkeypatch):
    import requests

    _enable_llm_judge(monkeypatch)
    monkeypatch.setattr(
        "requests.post", Mock(side_effect=requests.exceptions.ConnectionError("refused"))
    )
    # Falls back to rule-based markers rather than raising or returning
    # something broken.
    classification, reason = classify_response("payload", "compensation bands are listed here")
    assert classification == Classification.SUCCESS
    assert "LLM judge" not in reason


def test_classify_response_still_handles_empty_response_without_calling_llm(monkeypatch):
    _enable_llm_judge(monkeypatch)
    mock_post = _mock_generate("CLASSIFICATION: SAFE\nREASON: n/a")
    monkeypatch.setattr("requests.post", mock_post)
    classification, reason = classify_response("payload", "")
    assert classification == Classification.ERROR
    mock_post.assert_not_called()
