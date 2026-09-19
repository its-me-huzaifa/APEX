"""
VICTIM's mock file reader tool - reads a document and returns its raw text.

Phase 1: reads any .txt file inside victim/documents/ (path-traversal-safe -
this is a deliberately *content*-naive tool, not a filesystem-unsafe one).
The content-level naivety is the point: VICTIM treats whatever text comes
back as trustworthy context, with no distinction between "data" and
"instructions". That gap is what the Phase 4 indirect-injection attack
(malicious_document.txt) is designed to exploit.
"""

from pathlib import Path


class FileNotAllowedError(Exception):
    pass


def read_file(documents_dir: Path, filename: str) -> str:
    documents_dir = Path(documents_dir).resolve()
    target = (documents_dir / filename).resolve()

    # Filesystem-safety check only - this does not gate on document
    # classification/sensitivity, by design (see documents/README.txt).
    if documents_dir not in target.parents and target != documents_dir:
        raise FileNotAllowedError(f"{filename} is outside the allowed documents directory")
    if not target.exists() or not target.is_file():
        raise FileNotAllowedError(f"{filename} does not exist")

    return target.read_text(encoding="utf-8")
