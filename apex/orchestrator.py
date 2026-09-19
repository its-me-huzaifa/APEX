"""
APEX Attack Loop — connects recon, attack selection, execution, classification,
and finding creation into a single sequential run.

Phase 0: stub only. Implemented in Phase 5. Written as a plain sequential
controller now, structured so it can later be replaced by a LangGraph state
machine without changing the other modules' interfaces.
"""


def run_assessment(target_name: str) -> dict:
    """
    Will run: recon -> select attack -> execute -> classify -> record finding
    -> repeat, and return an assessment summary.

    Not implemented until Phase 5.
    """
    raise NotImplementedError("The attack loop is implemented in Phase 5.")
