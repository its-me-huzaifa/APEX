"""
LLMProvider abstraction.

Phase 1: provider selection is now implemented. RuleBasedProvider (zero cost,
zero dependency) is the default and is used unless config.USE_OLLAMA is True,
in which case LocalOllamaProvider is used - that class is still a Phase-1+
optional stub (see llm/ollama_provider.py) and is not required for the
prototype to work end to end.
"""

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Return a text completion for `prompt`."""
        raise NotImplementedError


_provider_instance: LLMProvider | None = None


def get_provider() -> LLMProvider:
    """Returns a cached, configured LLMProvider (RuleBasedProvider by default)."""
    global _provider_instance
    if _provider_instance is not None:
        return _provider_instance

    import config

    if config.USE_OLLAMA:
        from llm.ollama_provider import LocalOllamaProvider

        _provider_instance = LocalOllamaProvider(model=config.OLLAMA_MODEL)
    else:
        from llm.rule_based import RuleBasedProvider

        _provider_instance = RuleBasedProvider()

    return _provider_instance
