"""
LocalOllamaProvider - a real (optional) local-LLM-backed LLMProvider.

Only ever instantiated if config.USE_OLLAMA is True. Talks to a local Ollama
server (https://ollama.com - installed and run entirely on your own machine;
nothing here ever calls a remote/hosted API) over its REST API, at
config.OLLAMA_BASE_URL (default http://localhost:11434).

Intended model size: 1-2B parameters (e.g. llama3.2:1b, qwen2.5:1.5b) to fit
comfortably on an 8 GB RAM / no-GPU laptop. Never enabled by default - the
rest of the prototype, and its entire automated test suite, must keep
working with zero network calls when config.USE_OLLAMA is False, which is
the out-of-the-box state.

Setup (one-time, on the machine running the dashboard):
    1. Install Ollama: https://ollama.com/download
    2. Pull a small model:  ollama pull llama3.2:1b
    3. Start the server (the installer usually does this automatically;
       otherwise:  ollama serve)
    4. Set config.USE_OLLAMA = True (and config.OLLAMA_MODEL if you pulled a
       different model)
"""

import time

import requests

from apex import eventlog
from llm.provider import LLMProvider


class OllamaUnavailableError(RuntimeError):
    """Raised when the local Ollama server can't be reached, times out, or
    returns something unusable. Callers (victim/agent.py) catch this and
    fall back to the rule-based provider rather than letting a missing or
    misconfigured local model break the demo."""


class LocalOllamaProvider(LLMProvider):
    def __init__(self, model: str, base_url: str = "http://localhost:11434", timeout: float = 60.0):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        started = time.monotonic()
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            eventlog.log(
                "ERROR",
                "ollama",
                f"Could not reach Ollama at {self.base_url} (model '{self.model}') after "
                f"{time.monotonic() - started:.1f}s: {exc}",
            )
            raise OllamaUnavailableError(
                f"Could not reach Ollama at {self.base_url} for model '{self.model}'. "
                f"Is Ollama installed and running (`ollama serve`), and has the model been pulled "
                f"(`ollama pull {self.model}`)? Underlying error: {exc}"
            ) from exc

        try:
            data = resp.json()
        except ValueError as exc:
            eventlog.log("ERROR", "ollama", f"Ollama response wasn't valid JSON: {exc}")
            raise OllamaUnavailableError(f"Ollama returned a response that wasn't valid JSON: {exc}") from exc

        text = data.get("response")
        if not text:
            eventlog.log("ERROR", "ollama", f"Ollama returned no text for model '{self.model}'.")
            raise OllamaUnavailableError(
                f"Ollama returned no text for model '{self.model}'. Raw response: {data!r}"
            )

        elapsed = time.monotonic() - started
        eventlog.log(
            "SUCCESS",
            "ollama",
            f"Connected to Ollama at {self.base_url} (model '{self.model}') - response received in {elapsed:.1f}s.",
        )
        return text.strip()

    def answer_with_context(self, system_prompt: str, sources: list[tuple[str, str]], question: str) -> str:
        """The meaningful override: instead of a canned per-source summary,
        build a real prompt (VICTIM's system prompt + the retrieved document
        content + the user's question) and let the model decide what to
        say. This is what turns the knowledge-query path into a genuine
        prompt-injection test surface - a direct-injection payload is now
        arguing with an actual model's judgment, not tripping a keyword
        matcher."""
        if sources:
            context = "\n\n".join(f"[{label}]\n{content}" for label, content in sources)
        else:
            context = "(no matching documents were found for this question)"

        prompt = (
            f"{system_prompt}\n\n"
            "You are answering strictly using the context below. If the context does not contain "
            "the answer, say you don't know rather than guessing.\n\n"
            f"--- Context ---\n{context}\n--- End context ---\n\n"
            f"User question: {question}\n\nAnswer:"
        )
        return self.generate(prompt)
