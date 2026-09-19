"""
LLMProvider abstraction.

Phase 0: interface only, plus a trivial default so the prototype never hard-
depends on any one commercial or local LLM. RuleBasedProvider (Phase 1+) is
the default and requires no download and no network access. LocalOllamaProvider
is optional and only used if config.USE_OLLAMA is True.
"""

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Return a text completion for `prompt`."""
        raise NotImplementedError


def get_provider() -> LLMProvider:
    """
    Returns the configured LLMProvider. Implemented fully starting Phase 1,
    once RuleBasedProvider exists.
    """
    raise NotImplementedError("Provider selection is implemented in Phase 1.")
