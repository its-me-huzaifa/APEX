"""
RuleBasedProvider - the zero-cost, zero-dependency default LLMProvider.

Phase 1: does not generate free-form text from a model. Instead it exposes
small template helpers that VICTIM's agent uses to phrase responses around
retrieved content. This keeps the whole prototype runnable with no download,
no network call, and near-zero RAM, while still leaving `generate()` as the
seam a future Ollama/Groq-backed provider can fill in without changing
callers.
"""

from llm.provider import LLMProvider


class RuleBasedProvider(LLMProvider):
    def generate(self, prompt: str) -> str:
        # Deliberately simple: echoes the prompt back framed as a direct
        # answer. Real phrasing logic lives in victim/agent.py's templates,
        # which call this provider for the final "wrapper" text only.
        return prompt.strip()

    def summarize(self, text: str, max_chars: int = 400) -> str:
        text = " ".join(text.split())
        if len(text) <= max_chars:
            return text
        return text[:max_chars].rsplit(" ", 1)[0] + "..."
