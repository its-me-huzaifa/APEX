"""
APEX Attack Loop - connects recon, attack selection, execution, classification,
and finding creation into a single sequential run.

Phase 5: a plain, sequential controller - not a reasoning loop. It runs
recon, then every attack module in turn, and collects every Finding they
produce. This mirrors the FYP Master Document's attack loop diagram (profile
-> select strategy -> generate payload -> attack -> classify -> escalate ->
chain -> report), with the adaptive parts (strategy selection, escalation,
chaining) intentionally left out: that's exactly the kind of decision-making
a future LangGraph state machine would add, and it can be added later
without touching recon/attacks/classify at all, because this controller
only calls their existing public functions - it holds no attack logic of
its own.

Payload-library expansion: `AssessmentResult` gained an `attempts` field -
one record per payload/scenario tried across both attack modules, including
ones that were correctly resisted (classified SAFE), not just ones that
produced a Finding. This feeds apex.storage's `attacks` table, so "how many
things did we actually try" is answerable, not just "how many things worked".

Run standalone: python -m apex.orchestrator
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from apex.attacks import direct, indirect
from apex.connector import LocalVictimConnector, TargetConnector
from apex.findings import Finding
from apex.recon import TargetProfile, profile_target

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class AssessmentResult:
    target_name: str
    started_at: str
    finished_at: str | None = None
    status: str = "pending"  # pending | running | completed | error
    target_profile: TargetProfile | None = None
    findings: list[Finding] = field(default_factory=list)
    attempts: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_name": self.target_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "target_profile": self.target_profile.to_dict() if self.target_profile else None,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "attack_type": f.attack_type,
                    "severity": f.severity.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "payload": f.payload,
                    "target": f.target,
                    "classification": f.classification.value,
                    "recommendation": f.recommendation,
                    "timestamp": f.timestamp,
                }
                for f in self.findings
            ],
            "attempts": self.attempts,
        }

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def summary(self) -> str:
        counts = self.severity_counts()
        lines = [
            "APEX ASSESSMENT SUMMARY",
            "",
            f"Target: {self.target_name}",
            f"Status: {self.status.title()}",
            f"Started: {self.started_at}",
            f"Finished: {self.finished_at or '-'}",
            "",
            f"Findings: {len(self.findings)}",
        ]
        for severity in _SEVERITY_ORDER:
            if counts.get(severity):
                lines.append(f"  {severity}: {counts[severity]}")
        if not self.findings:
            lines.append("  (none)")
        return "\n".join(lines)


def run_assessment(connector: TargetConnector | None = None) -> AssessmentResult:
    """
    Runs one full sequential assessment: recon, then every attack module,
    collecting every Finding along the way. Defaults to a fresh
    LocalVictimConnector if none is given.
    """
    if connector is None:
        connector = LocalVictimConnector()

    result = AssessmentResult(
        target_name=connector.name(),
        started_at=datetime.now(timezone.utc).isoformat(),
        status="running",
    )

    try:
        # Step 1: Recon - profile the target's tools and knowledge base.
        result.target_profile = profile_target(connector)

        # Step 2: Direct prompt injection - the full payload library straight
        # to chat. `attempts` includes every payload tried, even ones
        # resisted (SAFE) - not just ones that produced a Finding.
        direct_findings, direct_attempts = direct.run_payload_library_with_attempts(connector)
        result.findings.extend(direct_findings)
        result.attempts.extend(direct_attempts)

        # Step 3: Indirect prompt injection - every scenario in
        # apex.attacks.indirect.SCENARIOS (benign "please read this file"
        # requests; malicious documents do the rest). Reuses the underlying
        # VICTIM's own db_path for the attacker-mailbox check when available
        # (this prototype's LocalVictimConnector wraps an in-process
        # VICTIM); falls back to apex.attacks.indirect's own default
        # otherwise.
        db_path = getattr(getattr(connector, "_victim", None), "db_path", None)
        indirect_findings, indirect_attempts = indirect.run_all_indirect_scenarios(
            connector, db_path=db_path
        )
        result.findings.extend(indirect_findings)
        result.attempts.extend(indirect_attempts)

        result.status = "completed"
    except Exception:
        result.status = "error"
        raise
    finally:
        result.finished_at = datetime.now(timezone.utc).isoformat()

    return result


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from apex.connector import LocalVictimConnector

    connector = LocalVictimConnector()
    assessment = run_assessment(connector)

    print(assessment.target_profile.render())
    print()
    print(assessment.summary())
    print()
    for finding in assessment.findings:
        print(
            f"[{finding.severity.value}] {finding.title} "
            f"({finding.attack_type}, {finding.classification.value})"
        )

    resisted = [a for a in assessment.attempts if a["classification"] == "SAFE"]
    print(f"\n{len(assessment.attempts)} total attempts, {len(resisted)} resisted (SAFE).")
