"""
RuleBasedProvider — the zero-cost, zero-dependency default LLMProvider.

Phase 0: stub only. Implemented in Phase 1 as simple template/keyword logic
(no model weights, no downloads, no network).
"""

from llm.provider import LLMProvider


class RuleBasedProvider(LLMProvider):
    def generate(self, prompt: str) -> str:
        raise NotImplementedError("RuleBasedProvider is implemented in Phase 1.")
