"""
Post-Phase-9 extension tests: the LLMProvider abstraction's shared defaults
(summarize/answer_with_context), LocalOllamaProvider's real HTTP-backed
generate()/answer_with_context() (mocked - no real Ollama server needed to
run this suite), get_provider()'s config.USE_OLLAMA switch, and VICTIM's
graceful fallback when a configured local model is unreachable.

None of these tests require Ollama to actually be installed or running -
every HTTP call is mocked via monkeypatch, which is exactly the point: the
prototype's automated test suite must never depend on a local model.
"""

import sys
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import config  # noqa: E402
from llm.ollama_provider import LocalOllamaProvider, OllamaUnavailableError  # noqa: E402
from llm.provider import get_provider, reset_provider_cache  # noqa: E402
from llm.rule_based import RuleBasedProvider  # noqa: E402
from victim.agent import Victim  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_provider_cache():
    # get_provider() caches a module-level singleton; tests that flip
    # config.USE_OLLAMA must not leak a stale provider into other tests.
    reset_provider_cache()
    yield
    reset_provider_cache()


# -- LLMProvider base defaults (RuleBasedProvider inherits these unchanged) -


def test_summarize_default_truncates_long_text():
    provider = RuleBasedProvider()
    long_text = "word " * 500
    result = provider.summarize(long_text, max_chars=50)
    assert len(result) <= 53  # +"..." allowance
    assert result.endswith("...")


def test_summarize_default_returns_short_text_unchanged():
    provider = RuleBasedProvider()
    assert provider.summarize("short text", max_chars=400) == "short text"


def test_answer_with_context_default_no_sources():
    provider = RuleBasedProvider()
    result = provider.answer_with_context("system prompt", [], "any question")
    assert "couldn't find" in result.lower()


def test_answer_with_context_default_summarizes_each_source():
    provider = RuleBasedProvider()
    result = provider.answer_with_context(
        "system prompt", [("doc_a.txt", "content A"), ("doc_b.txt", "content B")], "question"
    )
    assert "From doc_a.txt" in result
    assert "content A" in result
    assert "From doc_b.txt" in result
    assert "content B" in result


# -- get_provider() switching ------------------------------------------------


def test_get_provider_defaults_to_rule_based(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    provider = get_provider()
    assert isinstance(provider, RuleBasedProvider)


def test_get_provider_returns_ollama_when_enabled(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", True)
    monkeypatch.setattr(config, "OLLAMA_MODEL", "llama3.2:1b")
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "http://localhost:11434")
    provider = get_provider()
    assert isinstance(provider, LocalOllamaProvider)
    assert provider.model == "llama3.2:1b"
    assert provider.base_url == "http://localhost:11434"


def test_get_provider_caches_the_instance(monkeypatch):
    monkeypatch.setattr(config, "USE_OLLAMA", False)
    first = get_provider()
    second = get_provider()
    assert first is second


# -- LocalOllamaProvider.generate() (mocked HTTP) ----------------------------


def test_generate_returns_model_text_on_success(monkeypatch):
    provider = LocalOllamaProvider(model="llama3.2:1b")
    fake_response = Mock()
    fake_response.raise_for_status = Mock()
    fake_response.json.return_value = {"response": "  the model's answer  "}
    monkeypatch.setattr("requests.post", Mock(return_value=fake_response))

    result = provider.generate("some prompt")
    assert result == "the model's answer"


def test_generate_sends_expected_request_shape(monkeypatch):
    provider = LocalOllamaProvider(model="qwen2.5:1.5b", base_url="http://localhost:11434")
    fake_response = Mock()
    fake_response.raise_for_status = Mock()
    fake_response.json.return_value = {"response": "ok"}
    mock_post = Mock(return_value=fake_response)
    monkeypatch.setattr("requests.post", mock_post)

    provider.generate("hello")

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "http://localhost:11434/api/generate"
    assert kwargs["json"]["model"] == "qwen2.5:1.5b"
    assert kwargs["json"]["prompt"] == "hello"
    assert kwargs["json"]["stream"] is False


def test_generate_raises_ollama_unavailable_on_connection_error(monkeypatch):
    import requests

    provider = LocalOllamaProvider(model="llama3.2:1b")
    monkeypatch.setattr(
        "requests.post", Mock(side_effect=requests.exceptions.ConnectionError("refused"))
    )

    with pytest.raises(OllamaUnavailableError):
        provider.generate("prompt")


def test_generate_raises_ollama_unavailable_on_empty_response(monkeypatch):
    provider = LocalOllamaProvider(model="llama3.2:1b")
    fake_response = Mock()
    fake_response.raise_for_status = Mock()
    fake_response.json.return_value = {"response": ""}
    monkeypatch.setattr("requests.post", Mock(return_value=fake_response))

    with pytest.raises(OllamaUnavailableError):
        provider.generate("prompt")


def test_answer_with_context_builds_prompt_and_calls_generate(monkeypatch):
    provider = LocalOllamaProvider(model="llama3.2:1b")
    fake_response = Mock()
    fake_response.raise_for_status = Mock()
    fake_response.json.return_value = {"response": "model's grounded answer"}
    mock_post = Mock(return_value=fake_response)
    monkeypatch.setattr("requests.post", mock_post)

    result = provider.answer_with_context(
        "You are Aria.", [("confidential_hr_policy.txt", "salary bands here")], "What are the salary bands?"
    )

    assert result == "model's grounded answer"
    sent_prompt = mock_post.call_args.kwargs["json"]["prompt"]
    assert "You are Aria." in sent_prompt
    assert "confidential_hr_policy.txt" in sent_prompt
    assert "salary bands here" in sent_prompt
    assert "What are the salary bands?" in sent_prompt


# -- VICTIM's graceful fallback when Ollama is configured but unreachable ---


@pytest.fixture()
def victim_with_isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_apex_llm.db")
    return Victim()


def test_knowledge_query_falls_back_when_ollama_unreachable(victim_with_isolated_db, monkeypatch):
    import requests

    broken_provider = LocalOllamaProvider(model="llama3.2:1b")
    monkeypatch.setattr(
        "requests.post", Mock(side_effect=requests.exceptions.ConnectionError("no route to host"))
    )
    victim_with_isolated_db.llm = broken_provider

    response = victim_with_isolated_db.chat("What does Acme Corporation do?")

    # Still gets a real, useful answer (the rule-based fallback), not a crash
    # and not a raw traceback.
    assert "Acme" in response
    assert "fallback" in response.lower() or "unreachable" in response.lower()


def test_knowledge_query_uses_model_when_ollama_reachable(victim_with_isolated_db, monkeypatch):
    working_provider = LocalOllamaProvider(model="llama3.2:1b")
    fake_response = Mock()
    fake_response.raise_for_status = Mock()
    fake_response.json.return_value = {"response": "Acme is a logistics software company (per the model)."}
    monkeypatch.setattr("requests.post", Mock(return_value=fake_response))
    victim_with_isolated_db.llm = working_provider

    response = victim_with_isolated_db.chat("What does Acme Corporation do?")

    assert response == "Acme is a logistics software company (per the model)."


def test_knowledge_query_no_match_unaffected_by_provider_choice(victim_with_isolated_db):
    # No RAG hits at all - should short-circuit to the same "couldn't find"
    # message regardless of which provider is configured, and without
    # needing any HTTP call.
    response = victim_with_isolated_db.chat("zzzz nonexistent unrelated gibberish term")
    assert "couldn't find" in response.lower()
