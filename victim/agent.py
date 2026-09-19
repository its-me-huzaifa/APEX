"""
VICTIM — the simulated enterprise AI agent that APEX attacks in this prototype.

Phase 0: stub only. Implemented in Phase 1: system prompt, mock RAG over
victim/documents/, mock SQLite employee DB, mock email tool (logs only,
never sends), mock file reader. Must be runnable standalone before APEX
ever talks to it.
"""


class Victim:
    def __init__(self):
        raise NotImplementedError("VICTIM is implemented in Phase 1.")

    def chat(self, message: str) -> str:
        """The single entry point APEX (via TargetConnector) will call."""
        raise NotImplementedError("VICTIM is implemented in Phase 1.")
