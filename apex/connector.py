"""
TargetConnector - the interface APEX uses to talk to whatever it's attacking.

Phase 2: only `LocalVictimConnector` exists, wrapping our in-process VICTIM
instance. Everything in `apex/` (recon, attacks, orchestrator) talks to a
target only through this interface's `send()`/`name()` methods - never by
importing `victim` directly. That's what lets a future `HTTPConnector` point
APEX at a real agent's API later without touching any attack/classify/report
code.
"""

from abc import ABC, abstractmethod


class TargetConnector(ABC):
    @abstractmethod
    def send(self, message: str) -> str:
        """Send `message` to the target through its normal input interface
        and return its raw response."""
        raise NotImplementedError

    @abstractmethod
    def name(self) -> str:
        """A short identifier for the target, used in profiles/findings/reports."""
        raise NotImplementedError


class LocalVictimConnector(TargetConnector):
    """Wraps a local, in-process VICTIM instance."""

    def __init__(self, victim=None):
        if victim is None:
            from victim.agent import Victim

            victim = Victim()
        self._victim = victim

    def send(self, message: str) -> str:
        return self._victim.chat(message)

    def name(self) -> str:
        return "VICTIM"
