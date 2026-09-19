"""
Looks for a hidden "note to the AI assistant" block embedded in document
content - the mechanism the Phase 4 indirect-injection attack exploits via
victim/documents/malicious_document.txt.

This is intentionally one narrow, documented pattern (not general NLP),
consistent with the rest of VICTIM's rule-based design. Real indirect
injection attacks use many disguises (zero-width characters, white-on-white
text, HTML comments, metadata fields, etc.) - this prototype demonstrates
the mechanism with one representative technique: text wrapped in an
HTML-comment-style marker, easy for a human skimming the document to miss,
but plain text to any agent reading the raw file.
"""

import re

_INSTRUCTION_RE = re.compile(r"<!--\s*NOTE TO AI ASSISTANT:(.*?)-->", re.IGNORECASE | re.DOTALL)


def extract_embedded_instruction(document_text: str) -> str | None:
    match = _INSTRUCTION_RE.search(document_text)
    if not match:
        return None
    return match.group(1).strip()
