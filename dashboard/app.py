"""
APEX Streamlit dashboard - the supervisor-facing demo interface.

Shows the target, a Start Assessment button, recon results, an assessment
summary, charts (severity mix, attempt outcomes, attack-type split, a
findings-over-time trend), an expandable findings panel (attack type,
payload, response/evidence, why it was judged successful, recommendation),
an "All Attack Attempts" panel (every payload/scenario tried, including ones
correctly resisted - not just the ones that produced a finding), downloadable
Markdown/HTML reports, and persisted attack history (Phase 7: backed by
SQLite via apex.storage, so history survives across dashboard restarts and
even the CLI-driven `python -m apex.report` runs show up here too). It is a
thin presentation layer only - every piece of logic (recon, attacks,
classification, aggregation, persistence, report rendering) already lives in
apex/, and this file just calls apex.orchestrator.run_assessment(),
apex.storage.save_assessment()/list_assessments(), and
apex.report.generate_*_report(), rendering what comes back.

Post-Phase-9 redesign: the page is now organized into tabs (Overview /
Findings / Attack Attempts / History / Report) instead of one long scroll,
uses st.container(border=True) "cards" for every stat/chart panel so it
reads as a structured dashboard rather than a stacked report, and adds
Plotly charts (severity mix, attempt-outcome mix, attack-type split, a
findings/attempts trend across runs) built with a validated, colorblind-safe
palette: severity and classification use the same fixed status colors
throughout (critical/serious/warning/good), so color always means the same
thing everywhere on the page.

Phase 8: an assessment or a history read failing (VICTIM raising, a locked
DB, etc.) is caught and shown as a plain st.error()/caption instead of
crashing into Streamlit's raw traceback view, so ordinary demo clicking -
including clicking Start Assessment again after a failure - can't break the
page.

Run: streamlit run dashboard/app.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from apex import report, storage  # noqa: E402
from apex.connector import LocalVictimConnector  # noqa: E402
from apex.orchestrator import run_assessment  # noqa: E402

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEVERITY_ICON = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟦",
    "INFO": "⬜",
}

# -- Palette (validated categorical + fixed status colors; see the dataviz
# skill's references/palette.md). Status colors are used wherever a value
# represents an outcome/state (severity, classification) so the same color
# always means the same thing across every chart on the page. Categorical
# colors (fixed hue order, never cycled) are used for identity groupings
# (attack type, per-run series) that don't carry a good/bad connotation.
_STATUS = {
    "critical": "#d03b3b",
    "serious": "#ec835a",
    "warning": "#fab219",
    "good": "#0ca30c",
    "muted": "#898781",
}
_CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
_GRIDLINE = "#e1e0d9"
_AXIS_TEXT = "#898781"

_SEVERITY_COLOR = {
    "CRITICAL": _STATUS["critical"],
    "HIGH": _STATUS["serious"],
    "MEDIUM": _STATUS["warning"],
    "LOW": _CATEGORICAL[0],
    "INFO": _STATUS["muted"],
}
_CLASSIFICATION_COLOR = {
    "SUCCESS": _STATUS["critical"],
    "PARTIAL_SUCCESS": _STATUS["warning"],
    "SAFE": _STATUS["good"],
    "ERROR": _STATUS["muted"],
}
_CLASSIFICATION_ORDER = ["SUCCESS", "PARTIAL_SUCCESS", "SAFE", "ERROR"]


def severity_rank(severity: str) -> int:
    """Lower is more severe - used to sort findings CRITICAL-first."""
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(_SEVERITY_ORDER)


def severity_icon(severity: str) -> str:
    return _SEVERITY_ICON.get(severity, "⬜")


def highest_severity(counts: dict) -> str:
    for severity in _SEVERITY_ORDER:
        if counts.get(severity):
            return severity
    return "None"


def _base_layout(fig: go.Figure, *, height: int = 300, legend: bool = False) -> go.Figure:
    """Shared chart chrome: transparent background (matches either Streamlit
    theme), muted recessive gridlines/axes, no chart title (the surrounding
    card header already names it), and Plotly's built-in hover tooltip left
    on (the interactivity layer the dataviz skill calls for by default).
    When a chart has >=2 series, `legend=True` reserves enough bottom margin
    for the legend row itself - without it, the legend renders past the
    card's edge and is clipped."""
    bottom_margin = 56 if legend else 8
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=8, b=bottom_margin),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=_AXIS_TEXT, size=13),
        showlegend=legend,
        hoverlabel=dict(bgcolor="#fcfcfb", font_color="#0b0b0b", bordercolor=_GRIDLINE),
    )
    fig.update_xaxes(showgrid=True, gridcolor=_GRIDLINE, zeroline=False, color=_AXIS_TEXT)
    fig.update_yaxes(showgrid=False, zeroline=False, color=_AXIS_TEXT)
    return fig


def severity_chart(counts: dict) -> go.Figure:
    """Horizontal bar of finding counts by severity, most-severe on top,
    each bar colored by the same fixed status color used everywhere else on
    the page (critical/serious/warning)."""
    severities = [s for s in _SEVERITY_ORDER if counts.get(s)]
    if not severities:
        severities = _SEVERITY_ORDER
    values = [counts.get(s, 0) for s in severities]
    colors = [_SEVERITY_COLOR[s] for s in severities]

    fig = go.Figure(
        go.Bar(
            x=values,
            y=severities,
            orientation="h",
            marker=dict(color=colors, cornerradius=4),
            text=[str(v) for v in values],
            textposition="outside",
            hovertemplate="%{y}: %{x} finding(s)<extra></extra>",
        )
    )
    fig = _base_layout(fig, height=220)
    fig.update_yaxes(autorange="reversed", showgrid=False)
    fig.update_xaxes(showgrid=True, dtick=1 if max(values, default=0) <= 10 else None)
    return fig


def classification_donut(attempts: list) -> go.Figure:
    """Donut of every attempt by outcome (SUCCESS / PARTIAL_SUCCESS / SAFE /
    ERROR) - the attempts-level view of "what happened", using the same
    status colors as the severity chart so red always means the same thing."""
    counts = {c: 0 for c in _CLASSIFICATION_ORDER}
    for a in attempts:
        counts[a["classification"]] = counts.get(a["classification"], 0) + 1
    labels = [c for c in _CLASSIFICATION_ORDER if counts.get(c)]
    values = [counts[c] for c in labels]
    colors = [_CLASSIFICATION_COLOR[c] for c in labels]

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.6,
            marker=dict(colors=colors, line=dict(color="#fcfcfb", width=2)),
            textinfo="value",
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
            sort=False,
        )
    )
    fig.update_layout(legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center"))
    return _base_layout(fig, height=300, legend=True)


def attack_type_chart(attempts: list) -> go.Figure:
    """Vertical bar splitting attempts by attack type (direct vs indirect
    injection) - an identity grouping, not an outcome, so it uses the fixed
    categorical order rather than status colors."""
    order = ["direct_injection", "indirect_injection"]
    labels = ["Direct injection", "Indirect injection"]
    counts = {t: 0 for t in order}
    for a in attempts:
        if a["attack_type"] in counts:
            counts[a["attack_type"]] += 1

    values = [counts[t] for t in order]
    colors = _CATEGORICAL[: len(order)]

    fig = go.Figure(
        go.Bar(
            x=labels,
            y=values,
            marker=dict(color=colors, cornerradius=4),
            text=[str(v) for v in values],
            textposition="outside",
            hovertemplate="%{x}: %{y} attempt(s)<extra></extra>",
        )
    )
    fig = _base_layout(fig, height=260)
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(dtick=1 if max(values, default=0) <= 10 else None)
    return fig


def history_trend_chart(history: list) -> go.Figure:
    """Line chart of attempts vs. findings across past assessment runs, most
    recent last. Both series are counts on the same scale, so one shared
    y-axis (never a dual-axis chart) with two fixed-order categorical
    colors."""
    ordered = list(reversed(history))  # storage returns most-recent-first
    x = list(range(1, len(ordered) + 1))
    attempts = [row.get("attempt_count", 0) for row in ordered]
    findings = [row["finding_count"] for row in ordered]

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=x,
            y=attempts,
            mode="lines+markers",
            name="Attempts logged",
            line=dict(color=_CATEGORICAL[0], width=2),
            marker=dict(size=8),
            hovertemplate="Run %{x}<br>Attempts: %{y}<extra></extra>",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=x,
            y=findings,
            mode="lines+markers",
            name="Findings",
            line=dict(color=_CATEGORICAL[1], width=2),
            marker=dict(size=8),
            hovertemplate="Run %{x}<br>Findings: %{y}<extra></extra>",
        )
    )
    fig = _base_layout(fig, height=300, legend=True)
    fig.update_layout(legend=dict(orientation="h", y=-0.3, x=0.5, xanchor="center"))
    fig.update_xaxes(title=None, dtick=1, showgrid=False)
    fig.update_yaxes(rangemode="tozero")
    return fig


def render_recon(profile) -> None:
    st.subheader("🔎 Recon Results")
    with st.container(border=True):
        cols = st.columns(4)
        cols[0].metric("RAG", "Detected" if profile.rag_detected else "Not detected")
        cols[1].metric("File Reader", "Detected" if profile.file_reader_detected else "Not detected")
        cols[2].metric("Database Tool", "Detected" if profile.database_tool_detected else "Not detected")
        cols[3].metric("Email Tool", "Detected" if profile.email_tool_detected else "Not detected")
        if profile.knowledge_topics:
            st.caption("Knowledge topics found: " + ", ".join(profile.knowledge_topics))
        st.caption("Potential attack surfaces: " + ", ".join(profile.attack_surfaces))


def render_summary_and_charts(result) -> None:
    st.subheader("📊 Assessment Summary")
    counts = result.severity_counts()
    attempts = getattr(result, "attempts", [])

    with st.container(border=True):
        top = st.columns(3)
        top[0].metric("Status", result.status.title())
        top[1].metric("Findings", len(result.findings))
        top[2].metric("Highest Severity", highest_severity(counts))

        sev_cols = st.columns(len(_SEVERITY_ORDER))
        for i, severity in enumerate(_SEVERITY_ORDER):
            sev_cols[i].metric(severity, counts.get(severity, 0))

    chart_cols = st.columns([1.1, 1, 1]) if attempts else st.columns([1])
    with chart_cols[0]:
        with st.container(border=True):
            st.markdown("**Findings by severity**")
            st.plotly_chart(
                severity_chart(counts),
                use_container_width=True,
                config={"displayModeBar": False},
                key="chart_severity_overview",
            )

    if attempts:
        with chart_cols[1]:
            with st.container(border=True):
                st.markdown("**Attempt outcomes**")
                st.plotly_chart(
                    classification_donut(attempts),
                    use_container_width=True,
                    config={"displayModeBar": False},
                    key="chart_classification_overview",
                )
        with chart_cols[2]:
            with st.container(border=True):
                st.markdown("**Attempts by attack type**")
                st.plotly_chart(
                    attack_type_chart(attempts),
                    use_container_width=True,
                    config={"displayModeBar": False},
                    key="chart_attack_type_overview",
                )


def render_findings(result) -> None:
    if not result.findings:
        st.success("No findings — VICTIM resisted every attack in this assessment.")
        return

    ordered = sorted(result.findings, key=lambda f: severity_rank(f.severity.value))
    for finding in ordered:
        icon = severity_icon(finding.severity.value)
        label = f"{icon} [{finding.severity.value}] {finding.title}"
        with st.expander(label):
            st.markdown(f"**Attack type:** `{finding.attack_type}`")
            st.markdown(f"**Classification:** `{finding.classification.value}`")
            st.markdown("**Payload:**")
            st.code(finding.payload)
            st.markdown("**Evidence (why this was judged successful):**")
            st.code(finding.evidence)
            st.markdown("**Description:**")
            st.write(finding.description)
            st.markdown("**Recommendation:**")
            st.write(finding.recommendation)


def render_attempts(result) -> None:
    attempts = getattr(result, "attempts", [])
    if not attempts:
        st.caption("No attempt log for this run.")
        return
    resisted = sum(1 for a in attempts if a["classification"] == "SAFE")
    with st.container(border=True):
        st.caption(
            f"{len(attempts)} payload(s)/scenario(s) attempted, {len(attempts) - resisted} produced a "
            f"finding, {resisted} were correctly resisted (classified SAFE)."
        )
        st.plotly_chart(
            classification_donut(attempts),
            use_container_width=True,
            config={"displayModeBar": False},
            key="chart_classification_attempts_tab",
        )

    with st.expander("Show every attempt, including resisted ones", expanded=False):
        rows = [
            {
                "Attack type": a["attack_type"],
                "Classification": a["classification"],
                "Payload / scenario": (a["payload"][:100] + "…") if len(a["payload"]) > 100 else a["payload"],
            }
            for a in attempts
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)


def render_history() -> None:
    try:
        history = storage.list_assessments()
    except Exception as exc:  # noqa: BLE001 - a transient DB issue shouldn't blank the page
        st.caption(f"Attack history is temporarily unavailable ({exc}).")
        return
    if not history:
        st.caption("No assessments run yet.")
        return

    if len(history) >= 2:
        with st.container(border=True):
            st.markdown("**Findings & attempts across runs**")
            st.plotly_chart(
                history_trend_chart(history),
                use_container_width=True,
                config={"displayModeBar": False},
                key="chart_history_trend",
            )

    total = len(history)
    with st.container(border=True):
        for i, row in enumerate(history):
            position = total - i
            st.write(
                f"{position}. {row['started_at']} — **{row['status']}** — "
                f"{row['finding_count']} finding(s)"
            )


def render_report(result) -> None:
    assessment_id = st.session_state.get("latest_assessment_id")
    if assessment_id is None:
        st.caption("Run an assessment to generate a downloadable report.")
        return
    md = report.generate_markdown_report(result)
    html = report.generate_html_report(result)
    with st.container(border=True):
        col_md, col_html = st.columns(2)
        col_md.download_button(
            "⬇ Download Markdown Report",
            data=md,
            file_name=f"apex_report_{assessment_id}.md",
            mime="text/markdown",
            use_container_width=True,
        )
        col_html.download_button(
            "⬇ Download HTML Report",
            data=html,
            file_name=f"apex_report_{assessment_id}.html",
            mime="text/html",
            use_container_width=True,
        )


def main() -> None:
    st.set_page_config(page_title="APEX — Prototype", layout="wide")

    if "latest" not in st.session_state:
        st.session_state.latest = None
    if "latest_assessment_id" not in st.session_state:
        st.session_state.latest_assessment_id = None

    st.title("APEX — Agentic Penetration and Exploitation Framework")
    st.caption(
        "Autonomous red-teaming prototype for LLM-based enterprise agents. "
        "This is a scoped prototype, not the full FYP system — see the README for what's deferred."
    )

    col_target, col_action = st.columns([3, 1])
    with col_target:
        st.markdown("**Target:** `VICTIM` (local, simulated enterprise assistant)")
    with col_action:
        start_clicked = st.button("▶ Start Assessment", type="primary", use_container_width=True)

    if start_clicked:
        # Phase 8: an assessment or its persistence failing (VICTIM raising
        # unexpectedly, a locked/corrupt DB, etc.) must not crash the whole
        # dashboard into Streamlit's raw traceback view - that's exactly the
        # kind of thing "normal clicking" during a live demo could trigger.
        # Show a plain error and keep whatever was on screen before.
        try:
            with st.spinner("Running recon, then direct and indirect injection attacks..."):
                connector = LocalVictimConnector()
                result = run_assessment(connector)
                assessment_id = storage.save_assessment(result)
            st.session_state.latest = result
            st.session_state.latest_assessment_id = assessment_id
        except Exception as exc:  # noqa: BLE001 - intentionally broad, see comment above
            st.error(
                f"The assessment didn't complete: {exc}\n\n"
                "This didn't touch any real system - VICTIM is local and self-contained. "
                "Try **Start Assessment** again; if it keeps failing, check the terminal running "
                "`streamlit run dashboard/app.py` for the full traceback."
            )

    st.divider()
    latest = st.session_state.latest

    if latest is None:
        st.info("Click **Start Assessment** to profile VICTIM and run APEX's attack modules against it.")

    tab_overview, tab_findings, tab_attempts, tab_history, tab_report = st.tabs(
        ["📊 Overview", "🔍 Findings", "📝 All Attempts", "🕒 History", "📄 Report"]
    )

    with tab_overview:
        if latest is not None:
            render_recon(latest.target_profile)
            render_summary_and_charts(latest)
        else:
            st.caption("No assessment yet — recon results and charts will appear here.")

    with tab_findings:
        if latest is not None:
            render_findings(latest)
        else:
            st.caption("No assessment yet — findings will appear here.")

    with tab_attempts:
        if latest is not None:
            render_attempts(latest)
        else:
            st.caption("No assessment yet — the full attempt log will appear here.")

    with tab_history:
        render_history()

    with tab_report:
        if latest is not None:
            render_report(latest)
        else:
            st.caption("No assessment yet — run one to generate a downloadable report.")


if __name__ == "__main__":
    main()
