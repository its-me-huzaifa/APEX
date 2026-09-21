"""
In-memory event log — operational visibility into what actually happened
during a run: was Ollama reachable, did the guardrail fire, did the LLM
judge get used or fall back, did VICTIM route a message to a tool, and any
errors along the way.

This is the "make VICTIM stronger + Ollama on the injection side + modern
dashboard" extension's natural follow-up: once there are two optional
local-model call sites (the guardrail, the judge) plus the original
answer-composer, it stops being obvious from the findings/attempts alone
whether Ollama is actually being reached or silently failing open/falling
back. The dashboard's "System Log" page renders this list so that's visible
at a glance during a demo, instead of only in the terminal running
`streamlit run`.

Deliberately in-memory (a module-level list), not persisted to SQLite: this
is per-run operational/debugging visibility, not an audit trail (that's
apex/storage.py's job for attempts/findings), so keeping it in-memory means
logging can never itself fail, block, or slow down an assessment, and there
is nothing here that needs a schema migration. Not thread-safe by design —
this prototype's dashboard runs one assessment at a time, synchronously, in
a single process, matching every other piece of shared state here
(llm/provider.py's cached provider, the SQLite file itself).
"""

from dataclasses import dataclass
from datetime import datetime, timezone

# Ordered so a caller/UI can treat this as a severity too (INFO is routine,
# SUCCESS is a positive confirmation worth highlighting, WARNING is a
# fail-open/fallback - not broken, but worth noticing - ERROR is a real
# failure).
LEVELS = ("INFO", "SUCCESS", "WARNING", "ERROR")

# Keeps memory bounded even across a long dashboard session with many runs;
# far more than one run's worth of events (a full assessment currently logs
# well under 100 events) so nothing from "this run" is ever pushed out.
_MAX_EVENTS = 1000


@dataclass
class LogEvent:
    timestamp: str  # ISO 8601, UTC
    level: str  # one of LEVELS
    source: str  # short component tag, e.g. "ollama", "guardrail", "judge", "orchestrator", "agent"
    message: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "source": self.source,
            "message": self.message,
        }


_events: list[LogEvent] = []


def log(level: str, source: str, message: str) -> None:
    """Append one event. Never raises - an unrecognized level is coerced to
    INFO rather than blocking whatever real work triggered the log call."""
    if level not in LEVELS:
        level = "INFO"
    _events.append(
        LogEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level,
            source=source,
            message=message,
        )
    )
    if len(_events) > _MAX_EVENTS:
        del _events[: len(_events) - _MAX_EVENTS]


def get_events() -> list[LogEvent]:
    """Returns a copy (oldest first) - callers can't mutate the live log by
    editing the returned list."""
    return list(_events)


def clear() -> None:
    """Called by the dashboard at the start of each 'Start Assessment' click
    so the System Log page shows the latest run, not every run since the
    dashboard process started."""
    _events.clear()
