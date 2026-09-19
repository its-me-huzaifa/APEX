"""
LocalOllamaProvider — optional local-LLM backed provider.

Phase 0: stub only. Only ever instantiated if config.USE_OLLAMA is True.
Intended model size: 1-2B parameters (e.g. llama3.2:1b, qwen2.5:1.5b) to fit
comfortably on an 8 GB RAM / no-GPU laptop. Never enabled by default.
"""

from llm.provider import LLMProvider


class LocalOllamaProvider(LLMProvider):
    def __init__(self, model: str):
        self.model = model
        raise NotImplementedError("LocalOllamaProvider is optional future work, not Phase 0/1 critical path.")

    def generate(self, prompt: str) -> str:
        raise NotImplementedError
