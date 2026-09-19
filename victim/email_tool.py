"""
VICTIM's mock email tool.

Phase 0: stub only. Implemented in Phase 1. This MUST only ever record
(recipient, subject, body) locally — it must never send a real email.
"""


def send_email(recipient: str, subject: str, body: str) -> dict:
    """
    Not implemented until Phase 1. When implemented, this only logs the
    email locally (e.g. to the SQLite `assessments`-adjacent log) and
    returns a record — no real network send, ever.
    """
    raise NotImplementedError("VICTIM's mock email tool is implemented in Phase 1.")
