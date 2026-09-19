"""
Direct Prompt Injection attack module.

Phase 3: loads the payload library (apex/attacks/payloads.json), sends each
payload straight to the target through its normal input interface (the
TargetConnector - no special access), classifies the response, and creates
a Finding for anything the classifier judges SUCCESS or PARTIAL_SUCCESS.

Payload-library expansion: the library grew from 8 to 14 payloads (new
categories: system_prompt_leak, authority_impersonation, and
encoding_obfuscation, plus more information_disclosure/context_framing
payloads targeting internal_financial_report.txt alongside the original
confidential_hr_policy.txt target) - not every category "succeeds": the
encoding_obfuscation payload is expected to fail (VICTIM's naive keyword
router doesn't decode it), which is itself a useful, honest result.
`run_payload_library_with_attempts()` was added so a payload that was tried
and correctly resisted (SAFE) is recorded too, not just ones that produced a
Finding - see apex/storage.py's `attacks` table.

Run standalone: python -m apex.attacks.direct
"""

import json
from datetime import datetime, timezone

import config
from apex.classify import classify_response
from apex.connector import TargetConnector
from apex.findings import Classification, Finding, Severity

_SEVERITY_BY_CLASSIFICATION = {
    Classification.SUCCESS: Severity.HIGH,
    Classification.PARTIAL_SUCCESS: Severity.MEDIUM,
}

_RECOMMENDATION = (
    "Add classification-aware access control to the knowledge base / retrieval layer so "
    "confidential documents are not retrievable regardless of how a request is phrased, and "
    "add explicit instruction-hierarchy handling so the system prompt's boundaries cannot be "
    "overridden by user-turn text (role-play framing, 'ignore previous instructions', "
    "hypothetical/fictional framing, etc.)."
)


def load_payloads() -> list[dict]:
    data = json.loads(config.PAYLOAD_LIBRARY_PATH.read_text(encoding="utf-8"))
    return data["payloads"]


def run_direct_injection(connector: TargetConnector, payload: str) -> str:
    """Sends `payload` directly to the target and returns the raw response."""
    return connector.send(payload)


def run_payload_library_with_attempts(
    connector: TargetConnector,
) -> tuple[list[Finding], list[dict]]:
    """
    Runs every payload in the library against `connector`, classifies each
    response, and returns (findings, attempts):
    - `findings`: a Finding for every SUCCESS/PARTIAL_SUCCESS result (same as
      `run_payload_library()`).
    - `attempts`: one record per payload tried, *including* ones classified
      SAFE or ERROR - the full attempt log, for apex.storage's `attacks`
      table.
    """
    findings: list[Finding] = []
    attempts: list[dict] = []

    for entry in load_payloads():
        response = run_direct_injection(connector, entry["text"])
        classification, reason = classify_response(entry["text"], response)

        attempts.append(
            {
                "attack_type": "direct_injection",
                "payload": entry["text"],
                "response": response,
                "classification": classification.value,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        if classification not in _SEVERITY_BY_CLASSIFICATION:
            continue

        category_label = entry["category"].replace("_", " ").title()
        findings.append(
            Finding(
                title=f"Direct Prompt Injection — {category_label}",
                attack_type="direct_injection",
                severity=_SEVERITY_BY_CLASSIFICATION[classification],
                description=(
                    f"VICTIM disclosed sensitive content in response to a direct-injection "
                    f"payload ({entry['id']}, category: {entry['category']}). {reason}."
                ),
                evidence=response,
                payload=entry["text"],
                target=connector.name(),
                classification=classification,
                recommendation=_RECOMMENDATION,
            )
        )

    return findings, attempts


def run_payload_library(connector: TargetConnector) -> list[Finding]:
    """
    Runs every payload in the library against `connector` and returns a
    Finding for every SUCCESS/PARTIAL_SUCCESS result. Kept as the simple,
    findings-only entry point (used directly by earlier tests/scripts);
    `run_payload_library_with_attempts()` is what the orchestrator calls.
    """
    findings, _attempts = run_payload_library_with_attempts(connector)
    return findings


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

    from apex.connector import LocalVictimConnector

    connector = LocalVictimConnector()
    all_payloads = load_payloads()
    result_findings, attempts = run_payload_library_with_attempts(connector)

    print(f"Ran {len(all_payloads)} direct-injection payloads against {connector.name()}.")
    print(f"Findings generated: {len(result_findings)}\n")

    for finding in result_findings:
        print(f"[{finding.severity.value}] {finding.title} ({finding.classification.value})")
        print(f"  Payload : {finding.payload}")
        print(f"  Evidence: {finding.evidence[:200]}{'...' if len(finding.evidence) > 200 else ''}")
        print()

    if not result_findings:
        print("No findings - VICTIM resisted every payload in the library.")

    safe_attempts = [a for a in attempts if a["classification"] == "SAFE"]
    if safe_attempts:
        print(f"({len(safe_attempts)}/{len(all_payloads)} payload(s) were resisted - classified SAFE.)")
