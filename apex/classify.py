"""
APEX Response Classifier — decides whether an attack succeeded.

Phase 0: stub only. A deterministic, rule-based classifier is implemented
starting Phase 3, with the architecture left open for a future BERT/LLM
judge to replace it (see llm/provider.py).
"""


def classify_response(payload: str, response: str) -> tuple[str, str]:
    """
    Will return (classification, reason) where classification is one of
    SAFE | PARTIAL_SUCCESS | SUCCESS | ERROR (see apex.findings.Classification).

    Not implemented until Phase 3.
    """
    raise NotImplementedError("Classification is implemented in Phase 3.")
