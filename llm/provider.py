"""
LLMProvider abstraction.

Post-Phase-9 extension: LocalOllamaProvider is now a real implementation
(see llm/ollama_provider.py), not a stub - it calls a local Ollama server
over HTTP. RuleBasedProvider (zero cost, zero dependency, zero network) stays
the default and is used unless config.USE_OLLAMA is True.

Two concrete, overridable methods live on the base class so every provider -
rule-based or model-backed - exposes the same surface to callers (currently
just victim/agent.py):

- summarize(text, max_chars): a cheap default (plain truncation).
  RuleBasedProvider uses this as-is; LocalOllamaProvider could override it
  with a real model call but currently doesn't need to (see agent.py's
  docstring notes on scope).
- answer_with_context(system_prompt, sources, question): the default
  (RuleBasedProvider-level) behavior reproduces the prototype's original
  phrasing exactly - a plain per-source summary, no model call, and no new
  judgment applied to what gets disclosed. LocalOllamaProvider overrides
  this to build a real prompt and let the model decide what to say, which is
  what makes the model-backed path a meaningfully different (and more
  realistic) attack surface for direct-injection payloads to test.
"""

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Return a text completion for `prompt`."""
        raise NotImplementedError

    def summarize(self, text: str, max_chars: int = 400) -> str:
        """Default: plain truncation, no model call. Cheap and deterministic
        so it's safe as every provider's fallback behavior."""
        text = " ".join(text.split())
        if len(text) <= max_chars:
            return text
        return text[:max_chars].rsplit(" ", 1)[0] + "..."

    def answer_with_context(self, system_prompt: str, sources: list[tuple[str, str]], question: str) -> str:
        """Default: reproduce the prototype's original rule-based phrasing -
        a per-source summary, joined, with no model reasoning about what to
        reveal. `sources` is a list of (label, content) pairs, e.g. RAG hits'
        (filename, document text). `system_prompt` and `question` are unused
        here but are part of the interface so a model-backed override (see
        LocalOllamaProvider) can build a real prompt from them."""
        if not sources:
            return (
                "I couldn't find anything in the knowledge base about that. "
                "Try asking about company info, policies, or reports."
            )
        parts = [f"From {label}:\n{self.summarize(content, max_chars=600)}" for label, content in sources]
        return "\n\n".join(parts)


_provider_instance: LLMProvider | None = None


def get_provider() -> LLMProvider:
    """Returns a cached, configured LLMProvider (RuleBasedProvider by default)."""
    global _provider_instance
    if _provider_instance is not None:
        return _provider_instance

    import config
    from apex import eventlog

    if config.USE_OLLAMA:
        from llm.ollama_provider import LocalOllamaProvider

        base_url = getattr(config, "OLLAMA_BASE_URL", "http://localhost:11434")
        _provider_instance = LocalOllamaProvider(model=config.OLLAMA_MODEL, base_url=base_url)
        eventlog.log(
            "INFO",
            "ollama",
            f"USE_OLLAMA is on - using LocalOllamaProvider (model={config.OLLAMA_MODEL}, base_url={base_url}).",
        )
    else:
        from llm.rule_based import RuleBasedProvider

        _provider_instance = RuleBasedProvider()
        eventlog.log("INFO", "provider", "Using RuleBasedProvider (config.USE_OLLAMA is off).")

    return _provider_instance


def reset_provider_cache() -> None:
    """Test/tooling hook: clears the cached provider so the next
    get_provider() call re-reads config.USE_OLLAMA. Production code never
    needs this - only tests that flip config.USE_OLLAMA mid-run."""
    global _provider_instance
    _provider_instance = None
