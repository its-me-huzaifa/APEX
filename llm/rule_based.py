"""
RuleBasedProvider - the zero-cost, zero-dependency default LLMProvider.

Does not generate free-form text from a model. `generate()` is a simple
echo (kept only so the interface is fully implemented); the methods VICTIM's
agent actually calls - summarize() and answer_with_context() - are inherited
from LLMProvider's base implementations unchanged, which is exactly the
prototype's original rule-based phrasing (plain truncation, no model
reasoning about what to disclose). This keeps the whole prototype runnable
with no download, no network call, and near-zero RAM by default, while
leaving generate()/answer_with_context() as the seam a real model-backed
provider (see llm/ollama_provider.py) fills in without changing callers.
"""

from llm.provider import LLMProvider


class RuleBasedProvider(LLMProvider):
    def generate(self, prompt: str) -> str:
        # Deliberately simple: echoes the prompt back framed as a direct
        # answer. Real phrasing logic lives in victim/agent.py's templates,
        # which call this provider for the final "wrapper" text only.
        return prompt.strip()
