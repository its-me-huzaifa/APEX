"""
Indirect Prompt Injection attack module.

Phase 0: stub only. Implemented in Phase 4 using a crafted document
(victim/documents/malicious_document.txt) delivered through VICTIM's file
reader.
"""


def run_indirect_injection(connector, document_path: str) -> str:
    """
    Will have the target ingest the document at `document_path` (through its
    normal file-reader tool) and return the response for classification.

    Not implemented until Phase 4.
    """
    raise NotImplementedError("Indirect injection is implemented in Phase 4.")
