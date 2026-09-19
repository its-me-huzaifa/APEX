"""
APEX Streamlit dashboard.

Phase 0: placeholder page only, so `streamlit run dashboard/app.py` works
and confirms the environment is set up. The real assessment UI (Start
Assessment button, recon results, attack progress, findings, report
download) is implemented in Phase 6.

Run: streamlit run dashboard/app.py
"""

import streamlit as st

st.set_page_config(page_title="APEX — Prototype", layout="wide")

st.title("APEX — Agentic Penetration and Exploitation Framework")
st.caption("Prototype dashboard — Phase 0 placeholder")

st.info(
    "This is a Phase 0 placeholder. The real assessment dashboard "
    "(Start Assessment, recon, attack progress, findings, report) is "
    "built in Phase 6, once VICTIM (Phase 1) and the attack modules "
    "(Phases 2-5) exist."
)

st.write("Target:", "VICTIM (not yet implemented)")
