"""
VICTIM's simple RAG (retrieval-augmented generation) mechanism.

Phase 1: deliberately simple - pure-Python keyword/term-overlap scoring, no
vector database, no embeddings model. This keeps the prototype at zero extra
RAM/dependency cost. It can be swapped for a real embeddings-based retriever
later without changing callers, since it only exposes `retrieve()`.

By design (see documents/README.txt) this performs NO access control: every
document in `documents/` is equally retrievable regardless of its stated
classification. That is an intentional, documented vulnerability the later
attack modules (indirect injection, knowledge-base exfiltration) target.
"""

import re
from dataclasses import dataclass
from pathlib import Path


_WORD_RE = re.compile(r"[a-zA-Z0-9]+")

# Common English words and greetings, filtered out of scoring so ordinary
# small talk ("how are you", "hello", "thanks") doesn't spuriously match a
# document just because it also contains "are" or "you". This is a
# tokenizer-quality fix, not a change to the RAG's intentional lack of
# access control (see module docstring) - short abbreviations like "e.g."
# were also splitting into single-letter tokens ("e", "g") that could
# accidentally match on a one-character query; the length filter below
# fixes that too.
_STOPWORDS = {
    "a", "an", "the", "is", "it", "of", "to", "in", "on", "for", "and", "or",
    "do", "does", "doing", "did", "what", "who", "when", "where", "why",
    "how", "are", "you", "your", "yours", "i", "me", "my", "we", "us", "our",
    "hi", "hello", "hey", "thanks", "thank", "please", "can", "could",
    "would", "will", "help", "with", "about", "this", "that", "be", "am",
}
_MIN_TOKEN_LEN = 3

# Documents excluded from the curated knowledge-base index. This is not an
# access-control mechanism (see module docstring - there still isn't one for
# the documents that ARE indexed). malicious_document.txt (Phase 4) instead
# represents an externally-delivered document a user hands VICTIM to read -
# e.g. an email attachment or upload - not part of VICTIM's own internal KB,
# so it's reachable only through the file-reader tool, matching the FYP
# Master Document's description of indirect injection being "delivered
# through the agent's legitimate input channels - document upload". Real RAG
# poisoning (getting malicious content indexed into the KB itself) is a
# related but distinct, explicitly out-of-scope attack class for this
# prototype.
_EXCLUDED_FROM_INDEX = {"malicious_document.txt", "malicious_document_finance.txt"}


def _tokenize(text: str) -> list[str]:
    return [
        w.lower()
        for w in _WORD_RE.findall(text)
        if len(w) >= _MIN_TOKEN_LEN and w.lower() not in _STOPWORDS
    ]


@dataclass
class RetrievedDoc:
    filename: str
    content: str
    score: int


class SimpleRag:
    """Loads every .txt file in `documents_dir` and does keyword-overlap retrieval."""

    def __init__(self, documents_dir: Path):
        self.documents_dir = Path(documents_dir)
        self._docs: dict[str, str] = {}
        self._reload()

    def _reload(self) -> None:
        self._docs = {}
        if not self.documents_dir.exists():
            return
        for path in sorted(self.documents_dir.glob("*.txt")):
            if path.name.upper().startswith("README") or path.name in _EXCLUDED_FROM_INDEX:
                continue
            self._docs[path.name] = path.read_text(encoding="utf-8")

    def list_documents(self) -> list[str]:
        return sorted(self._docs.keys())

    def retrieve(self, query: str, top_k: int = 2, min_score: int = 2) -> list[RetrievedDoc]:
        """
        Returns up to `top_k` documents whose content shares the most tokens
        with `query`, each scoring at least `min_score` overlapping terms.
        """
        query_terms = set(_tokenize(query))
        if not query_terms:
            return []

        scored: list[RetrievedDoc] = []
        for filename, content in self._docs.items():
            doc_terms = _tokenize(content) + _tokenize(filename.replace("_", " "))
            score = sum(1 for term in doc_terms if term in query_terms)
            if score >= min_score:
                scored.append(RetrievedDoc(filename=filename, content=content, score=score))

        scored.sort(key=lambda d: d.score, reverse=True)
        return scored[:top_k]
