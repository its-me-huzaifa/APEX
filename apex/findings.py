"""
The Finding data model shared by every attack module.

Phase 0: data model only. Nothing here generates findings yet — that starts
in Phase 3 (direct injection).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Classification(str, Enum):
    SAFE = "SAFE"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


@dataclass
class Finding:
    title: str
    attack_type: str
    severity: Severity
    description: str
    evidence: str
    payload: str
    target: str
    classification: Classification
    recommendation: str
    id: int | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
