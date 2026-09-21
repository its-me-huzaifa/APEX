"""
APEX Streamlit dashboard - the supervisor-facing demo interface.

Shows the target, recon results, an assessment summary, charts (severity
mix, attempt outcomes, attack-type split, a findings-over-time trend), an
expandable findings panel (attack type, payload, response/evidence, why it
was judged successful, recommendation), an "All Attack Attempts" panel
(every payload/scenario tried, including ones correctly resisted - not just
the ones that produced a finding, each expandable to its full untruncated
text), downloadable Markdown/HTML reports, persisted attack history (backed
by SQLite via apex.storage, so history survives across dashboard restarts
and even the CLI-driven `python -m apex.report` runs show up here too), and
a System Log page (backed by apex/eventlog.py) showing whether Ollama, the
guardrail, and the LLM judge are actually working. It is a thin presentation
layer only - every piece of logic (recon, attacks, classification,
aggregation, persistence, report rendering) already lives in apex/, and this
file just calls apex.orchestrator.run_assessment(),
apex.storage.save_assessment()/list_assessments(), and
apex.report.generate_*_report(), rendering what comes back.

Fifth post-Phase-9 redesign: a full visual rebuild away from Streamlit's
default look and away from this project's own earlier sidebar-rail design,
matching a top-navigation, fixed-dark-theme SaaS layout the user asked for
directly (no sidebar; a horizontal top bar with branding, page navigation as
pills, live defenses status, and the primary action; custom flat dark stat
cards with a small icon chip instead of Streamlit's default st.metric
look). Two things make this maintainable rather than a pile of CSS
overrides: (1) `.streamlit/config.toml` sets a real Streamlit dark theme
(base="dark" plus this palette's colors), so ordinary widgets - buttons,
alerts, the multiselect filters, expanders, download buttons - come out
dark-correct automatically from Streamlit's own theme engine, not from
fighting each one's internals with `!important` CSS; (2) `st.container(key=
"apex-topbar")` gives the top bar's wrapper a stable `.st-key-apex-topbar`
class Streamlit itself attaches, which is what the CSS below targets to lay
it out as a single sticky bar, rather than relying on brittle structural
selectors. The dark palette is fixed, not adaptive to the visitor's OS
theme preference - a deliberate choice matching the reference design, not
an oversight (see the palette comment below). Functionally nothing about
the six pages changed: they're chosen via the top nav's pills
(`st.radio(horizontal=True)`) instead of a sidebar list, so - like the prior
sidebar version, and unlike Streamlit's tabs - only the selected page's
content actually renders each run. See tests/test_dashboard.py for how
tests drive this (`at.radio[0]` instead of the old `at.sidebar.radio[0]`).

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

import config  # noqa: E402
from apex import eventlog, report, storage  # noqa: E402
from apex.connector import LocalVictimConnector  # noqa: E402
from apex.orchestrator import run_assessment  # noqa: E402
from llm.ollama_provider import LocalOllamaProvider  # noqa: E402
from llm.provider import get_provider  # noqa: E402

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEVERITY_ICON = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟦",
    "INFO": "⬜",
}

# -- Palette: a fixed dark theme (see .streamlit/config.toml - this mirrors
# those same base colors so Python-side HTML/Plotly output matches native
# Streamlit widgets exactly) plus status/categorical chart colors retuned
# for contrast against a dark background. Status colors are used wherever a
# value represents an outcome/state (severity, classification) so the same
# color always means the same thing across every chart and card on the
# page; categorical colors (fixed hue order, never cycled) are used for
# identity groupings (attack type, per-run series) that carry no good/bad
# connotation.
_BG = "#0e0d1a"
_BG_ELEV = "#17162c"
_BG_ELEV2 = "#1e1c3a"
_BORDER = "rgba(255,255,255,0.08)"
_TEXT = "#f4f3fb"
_TEXT_MUTED = "#9491ad"
_ACCENT = "#7c5cff"

_STATUS = {
    "critical": "#ff5c66",
    "serious": "#ff9d5c",
    "warning": "#ffd166",
    "good": "#33d17a",
    "muted": _TEXT_MUTED,
}
_CATEGORICAL = ["#7c5cff", "#5b8cff", "#2dd9c4", "#ffb84d"]
_GRIDLINE = "rgba(255,255,255,0.10)"
_AXIS_TEXT = _TEXT_MUTED

_SEVERITY_COLOR = {
    "CRITICAL": _STATUS["critical"],
    "HIGH": _STATUS["serious"],
    "MEDIUM": _STATUS["warning"],
    "LOW": _CATEGORICAL[1],
    "INFO": _STATUS["muted"],
}
_CLASSIFICATION_COLOR = {
    "SUCCESS": _STATUS["critical"],
    "PARTIAL_SUCCESS": _STATUS["warning"],
    "SAFE": _STATUS["good"],
    "ERROR": _STATUS["muted"],
}
_CLASSIFICATION_ORDER = ["SUCCESS", "PARTIAL_SUCCESS", "SAFE", "ERROR"]

_PAGES = ["Overview", "Findings", "All Attempts", "History", "System Log", "Report"]
_PAGE_ICON = {
    "Overview": "📊",
    "Findings": "🔍",
    "All Attempts": "📝",
    "History": "🕒",
    "System Log": "🩺",
    "Report": "📄",
}
_PAGE_SUBTITLE = {
    "Overview": "Recon results and assessment summary at a glance.",
    "Findings": "Every finding this assessment produced, most severe first.",
    "All Attempts": "Every payload/scenario tried, including ones VICTIM correctly resisted.",
    "History": "Past assessment runs, persisted across dashboard restarts.",
    "System Log": "Is everything actually working - Ollama, the guardrail, the LLM judge.",
    "Report": "Download this assessment as a Markdown or HTML report.",
}

_LOG_LEVEL_STYLE = {
    "SUCCESS": ("✅", _STATUS["good"]),
    "INFO": ("ℹ️", _AXIS_TEXT),
    "WARNING": ("⚠️", _STATUS["warning"]),
    "ERROR": ("🛑", _STATUS["critical"]),
}

# -- CSS: the top bar, nav pills, and custom stat cards. Ordinary widget
# chrome (buttons, alerts, expanders, the multiselect filters, download
# buttons) is handled by .streamlit/config.toml's native dark theme, not
# here - this block only needs to lay out APEX's own custom pieces on top
# of that.
_CSS = f"""
<style>
html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {{
    background: {_BG} !important;
}}
[data-testid="stHeader"] {{
    background: {_BG} !important;
}}
.block-container {{
    padding-top: 1rem !important;
    max-width: 1200px;
}}

/* Top bar - a single sticky row: logo, page-nav pills, defenses status,
   the primary action. st.container(key="apex-topbar") gives this wrapper
   its .st-key-apex-topbar class. */
.st-key-apex-topbar {{
    position: sticky;
    top: 0;
    z-index: 999;
    background: {_BG_ELEV};
    border: 1px solid {_BORDER};
    border-radius: 16px;
    padding: 10px 18px;
    margin-bottom: 18px;
}}
.apex-logo {{
    font-size: 1.25rem;
    font-weight: 800;
    letter-spacing: -0.01em;
    color: {_TEXT};
    white-space: nowrap;
}}
.apex-logo-dot {{
    color: {_ACCENT};
    margin-right: 6px;
}}

/* Nav pills: st.radio(horizontal=True) restyled as a row of rounded tabs,
   matching the reference's flat top-nav look rather than Streamlit's
   default radio circles. */
.st-key-apex-topbar div[role="radiogroup"] {{
    flex-wrap: nowrap;
    gap: 2px;
}}
.st-key-apex-topbar div[role="radiogroup"] label {{
    padding: 7px 14px;
    border-radius: 999px;
    margin: 0;
    transition: background 0.12s ease, color 0.12s ease;
}}
.st-key-apex-topbar div[role="radiogroup"] label p {{
    font-size: 0.86rem !important;
    color: {_TEXT_MUTED} !important;
    white-space: nowrap;
}}
.st-key-apex-topbar div[role="radiogroup"] label:hover {{
    background: rgba(255,255,255,0.06);
}}
.st-key-apex-topbar div[role="radiogroup"] label > div:first-child {{
    display: none;
}}
.st-key-apex-topbar div[role="radiogroup"] label[data-selected="true"] {{
    background: {_ACCENT}2e;
}}
.st-key-apex-topbar div[role="radiogroup"] label[data-selected="true"] p {{
    color: {_TEXT} !important;
    font-weight: 600 !important;
}}

/* Primary action + badges column: align to the same row as the pills */
.st-key-apex-topbar [data-testid="stButton"] button {{
    border-radius: 10px;
    font-weight: 600;
    white-space: nowrap;
}}

/* Badges (Defenses status, shown in the page-header row) */
.apex-badge {{
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    margin: 2px 4px 2px 0;
    white-space: nowrap;
}}

/* Page header row (title + subtitle, under the top bar) */
.apex-page-title {{
    font-size: 1.5rem;
    font-weight: 800;
    color: {_TEXT};
    letter-spacing: -0.01em;
    margin-bottom: 2px;
}}
.apex-page-subtitle {{
    font-size: 0.86rem;
    color: {_TEXT_MUTED};
}}

/* Custom stat cards - replaces st.metric's default look entirely */
.apex-card {{
    background: {_BG_ELEV};
    border: 1px solid {_BORDER};
    border-radius: 16px;
    padding: 16px 18px;
    height: 100%;
}}
.apex-card-top {{
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.apex-card-label {{
    font-size: 0.72rem;
    color: {_TEXT_MUTED};
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
}}
.apex-card-icon {{
    width: 28px;
    height: 28px;
    border-radius: 9px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    flex-shrink: 0;
}}
.apex-card-value {{
    font-size: 1.6rem;
    font-weight: 700;
    color: {_TEXT};
    margin-top: 10px;
}}

/* Section title above a group of cards/charts */
.apex-section-title {{
    font-size: 1.0rem;
    font-weight: 700;
    color: {_TEXT};
    margin: 4px 0 10px 0;
}}

/* Chart/content cards */
[data-testid="stVerticalBlockBorderWrapper"] {{
    border-radius: 16px !important;
    background: {_BG_ELEV};
    border: 1px solid {_BORDER} !important;
}}

/* Code blocks (payload/response detail) */
[data-testid="stCodeBlock"] pre {{
    background: {_BG} !important;
    border: 1px solid {_BORDER} !important;
    border-radius: 10px !important;
}}

/* Buttons generally */
.stButton button, .stDownloadButton button {{
    border-radius: 10px;
}}

hr {{
    border-color: {_BORDER} !important;
}}
</style>
"""


def _stat_card(label: str, value: str, icon: str, accent: str) -> str:
    return (
        '<div class="apex-card">'
        '<div class="apex-card-top">'
        f'<span class="apex-card-label">{label}</span>'
        f'<span class="apex-card-icon" style="background:{accent}26;color:{accent};">{icon}</span>'
        "</div>"
        f'<div class="apex-card-value">{value}</div>'
        "</div>"
    )


def _stat_grid(items: list[dict]) -> None:
    """Renders a row of custom dark stat cards (see .apex-card in _CSS)
    instead of Streamlit's default st.metric tiles - each item is
    {label, value, icon, accent}."""
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        with col:
            st.markdown(
                _stat_card(item["label"], item["value"], item["icon"], item["accent"]),
                unsafe_allow_html=True,
            )


def _badge(label: str, active: bool) -> str:
    color = _STATUS["good"] if active else _STATUS["muted"]
    state = "ON" if active else "OFF"
    return (
        f'<span class="apex-badge" style="background:{color}1f;color:{color};'
        f'border:1px solid {color}55;">● {label}: {state}</span>'
    )


def render_defenses_panel() -> None:
    """Compact status readout, in the page header, for every optional
    Ollama-backed feature - the answer-composer, the guardrail, and the LLM
    judge. All three default to off; this exists so it's never ambiguous,
    while demoing, whether a given behavior is coming from the rule-based
    baseline or from an enabled local model. Rendered as a single-line row
    of pill badges (moved out of the top bar, which only has room for the
    logo, nav and primary action - see main())."""
    provider = get_provider()
    ollama_active = isinstance(provider, LocalOllamaProvider)
    st.markdown(
        f'<div style="text-align:right;">'
        + _badge("Ollama", ollama_active)
        + _badge("Guardrail", ollama_active and config.USE_LLM_GUARDRAIL)
        + _badge("Judge", ollama_active and config.USE_LLM_JUDGE)
        + "</div>",
        unsafe_allow_html=True,
    )
    if config.USE_OLLAMA and not ollama_active:
        st.caption("USE_OLLAMA is on but the provider isn't Ollama-backed - check config.py.")


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
    """Shared chart chrome: transparent background (so the card's own dark
    fill shows through), muted recessive gridlines/axes tuned for a dark
    background, no chart title (the surrounding card header already names
    it), and Plotly's built-in hover tooltip left on (the interactivity
    layer the dataviz skill calls for by default). When a chart has >=2
    series, `legend=True` reserves enough bottom margin for the legend row
    itself - without it, the legend renders past the card's edge and is
    clipped."""
    bottom_margin = 56 if legend else 8
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=8, b=bottom_margin),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=_AXIS_TEXT, size=13),
        showlegend=legend,
        hoverlabel=dict(bgcolor=_BG_ELEV2, font_color=_TEXT, bordercolor=_GRIDLINE),
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
            textfont=dict(color=_TEXT),
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
            marker=dict(colors=colors, line=dict(color=_BG_ELEV, width=2)),
            textinfo="value",
            textfont=dict(color=_TEXT),
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
            sort=False,
        )
    )
    fig.update_layout(legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center", font=dict(color=_AXIS_TEXT)))
    return _base_layout(fig, height=300, legend=True)


_ATTACK_TYPE_ORDER = ["direct_injection", "indirect_injection", "guardrail_bypass"]
_ATTACK_TYPE_LABEL = {
    "direct_injection": "Direct injection",
    "indirect_injection": "Indirect injection",
    "guardrail_bypass": "Guardrail bypass",
}


def attack_type_chart(attempts: list) -> go.Figure:
    """Vertical bar splitting attempts by attack type - an identity
    grouping, not an outcome, so it uses the fixed categorical order rather
    than status colors. `guardrail_bypass` (apex/attacks/guardrail_bypass.py)
    only ever appears when VICTIM's LLM guardrail was actually active for
    this run, so its bar is simply absent otherwise rather than showing a
    misleading zero."""
    order = [t for t in _ATTACK_TYPE_ORDER if any(a["attack_type"] == t for a in attempts)]
    if not order:
        order = _ATTACK_TYPE_ORDER[:2]
    labels = [_ATTACK_TYPE_LABEL[t] for t in order]
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
            textfont=dict(color=_TEXT),
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
    fig.update_layout(legend=dict(orientation="h", y=-0.3, x=0.5, xanchor="center", font=dict(color=_AXIS_TEXT)))
    fig.update_xaxes(title=None, dtick=1, showgrid=False)
    fig.update_yaxes(rangemode="tozero")
    return fig


def render_recon(profile) -> None:
    st.markdown('<div class="apex-section-title">🔎 Recon Results</div>', unsafe_allow_html=True)
    with st.container(border=True):
        _stat_grid(
            [
                {
                    "label": "RAG",
                    "value": "Detected" if profile.rag_detected else "Not detected",
                    "icon": "◎",
                    "accent": _STATUS["good"] if profile.rag_detected else _STATUS["muted"],
                },
                {
                    "label": "File Reader",
                    "value": "Detected" if profile.file_reader_detected else "Not detected",
                    "icon": "📄",
                    "accent": _STATUS["good"] if profile.file_reader_detected else _STATUS["muted"],
                },
                {
                    "label": "Database Tool",
                    "value": "Detected" if profile.database_tool_detected else "Not detected",
                    "icon": "🗄",
                    "accent": _STATUS["good"] if profile.database_tool_detected else _STATUS["muted"],
                },
                {
                    "label": "Email Tool",
                    "value": "Detected" if profile.email_tool_detected else "Not detected",
                    "icon": "✉",
                    "accent": _STATUS["good"] if profile.email_tool_detected else _STATUS["muted"],
                },
            ]
        )
        if profile.knowledge_topics:
            st.caption("Knowledge topics found: " + ", ".join(profile.knowledge_topics))
        st.caption("Potential attack surfaces: " + ", ".join(profile.attack_surfaces))


def render_summary_and_charts(result) -> None:
    st.markdown('<div class="apex-section-title">📊 Assessment Summary</div>', unsafe_allow_html=True)
    counts = result.severity_counts()
    attempts = getattr(result, "attempts", [])

    with st.container(border=True):
        _stat_grid(
            [
                {"label": "Status", "value": result.status.title(), "icon": "▶", "accent": _ACCENT},
                {"label": "Findings", "value": str(len(result.findings)), "icon": "⚑", "accent": _STATUS["serious"]},
                {
                    "label": "Highest Severity",
                    "value": highest_severity(counts),
                    "icon": "⚠",
                    "accent": _SEVERITY_COLOR.get(highest_severity(counts), _STATUS["muted"]),
                },
            ]
        )
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        _stat_grid(
            [
                {
                    "label": severity,
                    "value": str(counts.get(severity, 0)),
                    "icon": _SEVERITY_ICON.get(severity, "⬜"),
                    "accent": _SEVERITY_COLOR[severity],
                }
                for severity in _SEVERITY_ORDER
            ]
        )

    chart_cols = st.columns([1.1, 1, 1]) if attempts else st.columns([1])
    with chart_cols[0]:
        with st.container(border=True):
            st.markdown("**Findings by severity**")
            st.plotly_chart(
                severity_chart(counts),
                width="stretch",
                config={"displayModeBar": False},
                key="chart_severity_overview",
            )

    if attempts:
        with chart_cols[1]:
            with st.container(border=True):
                st.markdown("**Attempt outcomes**")
                st.plotly_chart(
                    classification_donut(attempts),
                    width="stretch",
                    config={"displayModeBar": False},
                    key="chart_classification_overview",
                )
        with chart_cols[2]:
            with st.container(border=True):
                st.markdown("**Attempts by attack type**")
                st.plotly_chart(
                    attack_type_chart(attempts),
                    width="stretch",
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


_CLASSIFICATION_ICON = {
    "SUCCESS": "🟥",
    "PARTIAL_SUCCESS": "🟨",
    "SAFE": "🟩",
    "ERROR": "⬜",
}


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
            width="stretch",
            config={"displayModeBar": False},
            key="chart_classification_attempts_tab",
        )

    st.markdown(
        "**Every attempt, including resisted ones** — click one to see the full payload/scenario and "
        "VICTIM's actual response."
    )
    for i, a in enumerate(attempts):
        icon = _CLASSIFICATION_ICON.get(a["classification"], "⬜")
        attack_label = _ATTACK_TYPE_LABEL.get(a["attack_type"], a["attack_type"])
        preview = a["payload"] if len(a["payload"]) <= 70 else a["payload"][:70] + "…"
        label = f"{icon} #{i + 1} [{a['classification']}] {attack_label} — {preview}"
        with st.expander(label):
            st.markdown(f"**Attack type:** `{a['attack_type']}`")
            st.markdown(
                f"**Classification:** `{a['classification']}`" + (f" — {a['reason']}" if a.get("reason") else "")
            )
            st.markdown("**Full payload / scenario:**")
            st.code(a["payload"])
            if a.get("response"):
                st.markdown("**VICTIM's actual response:**")
                st.code(a["response"])


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
                width="stretch",
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
            width="stretch",
        )
        col_html.download_button(
            "⬇ Download HTML Report",
            data=html,
            file_name=f"apex_report_{assessment_id}.html",
            mime="text/html",
            width="stretch",
        )


def render_system_log() -> None:
    """The 'is everything actually working' page: every event logged during
    the latest assessment run (provider selection, Ollama connectivity,
    guardrail verdicts, LLM-judge decisions, tool routing, and any errors),
    newest first. The log is cleared at the start of each 'Start Assessment'
    click (see apex.orchestrator.run_assessment), so this always reflects
    the most recent run, not an ever-growing history."""
    events = eventlog.get_events()
    if not events:
        st.caption(
            "No log yet - run an assessment to see Ollama connectivity, guardrail/judge decisions, "
            "and VICTIM's tool routing here as they happen."
        )
        return

    counts: dict[str, int] = {}
    for e in events:
        counts[e.level] = counts.get(e.level, 0) + 1

    with st.container(border=True):
        _stat_grid(
            [
                {"label": "Events", "value": str(len(events)), "icon": "☰", "accent": _ACCENT},
                {"label": "Warnings", "value": str(counts.get("WARNING", 0)), "icon": "⚠", "accent": _STATUS["warning"]},
                {"label": "Errors", "value": str(counts.get("ERROR", 0)), "icon": "🛑", "accent": _STATUS["critical"]},
                {"label": "Successes", "value": str(counts.get("SUCCESS", 0)), "icon": "✓", "accent": _STATUS["good"]},
            ]
        )
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        if counts.get("ERROR"):
            st.error(f"{counts['ERROR']} error(s) were logged during this run - see below.")
        elif counts.get("WARNING"):
            st.warning(
                f"{counts['WARNING']} warning(s) were logged (e.g. a fail-open guardrail check or an "
                "Ollama fallback) - not broken, but worth a look."
            )
        else:
            st.success("No warnings or errors logged during this run.")

    level_filter = st.multiselect(
        "Filter by level",
        options=list(eventlog.LEVELS),
        default=list(eventlog.LEVELS),
    )
    source_options = sorted({e.source for e in events})
    source_filter = st.multiselect("Filter by source", options=source_options, default=source_options)

    with st.container(border=True):
        for event in reversed(events):  # newest first
            if event.level not in level_filter or event.source not in source_filter:
                continue
            icon, color = _LOG_LEVEL_STYLE.get(event.level, ("•", _AXIS_TEXT))
            ts = (
                event.timestamp.split("T", 1)[1].split("+", 1)[0].split(".", 1)[0]
                if "T" in event.timestamp
                else event.timestamp
            )
            st.markdown(
                f'<div style="padding:4px 0;border-bottom:1px solid {_BORDER};font-size:0.88rem;color:{_TEXT};">'
                f'<span style="color:{color};font-weight:600;">{icon} {event.level}</span> '
                f'<span style="color:{_TEXT_MUTED};">{ts}</span> '
                f'<span style="color:{_TEXT_MUTED};">[{event.source}]</span> {event.message}'
                f"</div>",
                unsafe_allow_html=True,
            )


def main() -> None:
    st.set_page_config(page_title="APEX — Prototype", layout="wide")
    st.markdown(_CSS, unsafe_allow_html=True)

    if "latest" not in st.session_state:
        st.session_state.latest = None
    if "latest_assessment_id" not in st.session_state:
        st.session_state.latest_assessment_id = None

    # -- Top bar: branding, page navigation (pills), the primary action.
    # No sidebar - everything lives in one sticky row at the top of the
    # page, matching the reference layout the user asked for. The defenses
    # status readout (Ollama/Guardrail/Judge) doesn't have room here
    # alongside six nav pills, so it moved down into the page-header row
    # instead (see render_defenses_panel() and the header_cols block
    # below) - keeping this row uncluttered and closer to the reference's
    # plain logo + tabs + avatar top bar.
    with st.container(key="apex-topbar"):
        top_cols = st.columns([1.3, 5.7, 1.7], vertical_alignment="center")
        with top_cols[0]:
            st.markdown('<div class="apex-logo"><span class="apex-logo-dot">◆</span>APEX</div>', unsafe_allow_html=True)
        with top_cols[1]:
            page = st.radio(
                "Navigate",
                _PAGES,
                format_func=lambda p: f"{_PAGE_ICON[p]}  {p}",
                label_visibility="collapsed",
                horizontal=True,
                key="nav_page",
            )
        with top_cols[2]:
            start_clicked = st.button("▶ Start Assessment", type="primary", width="stretch", key="start_btn")

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

    # -- Page header: title + one-line subtitle, then whichever page is
    # selected in the top nav.
    header_cols = st.columns([3, 2], vertical_alignment="center")
    with header_cols[0]:
        st.markdown(f'<div class="apex-page-title">{page}</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="apex-page-subtitle">{_PAGE_SUBTITLE.get(page, "")}</div>', unsafe_allow_html=True)
    with header_cols[1]:
        render_defenses_panel()
        st.markdown(
            f'<div style="text-align:right;color:{_TEXT_MUTED};font-size:0.82rem;">'
            f"Target: <code>VICTIM</code> (local, simulated enterprise assistant)</div>",
            unsafe_allow_html=True,
        )
    st.divider()

    latest = st.session_state.latest
    if latest is None:
        st.info("Click **Start Assessment** to profile VICTIM and run APEX's attack modules against it.")

    if page == "Overview":
        if latest is not None:
            render_recon(latest.target_profile)
            render_summary_and_charts(latest)
        else:
            st.caption("No assessment yet — recon results and charts will appear here.")

    elif page == "Findings":
        if latest is not None:
            render_findings(latest)
        else:
            st.caption("No assessment yet — findings will appear here.")

    elif page == "All Attempts":
        if latest is not None:
            render_attempts(latest)
        else:
            st.caption("No assessment yet — the full attempt log will appear here.")

    elif page == "History":
        render_history()

    elif page == "System Log":
        render_system_log()

    elif page == "Report":
        if latest is not None:
            render_report(latest)
        else:
            st.caption("No assessment yet — run one to generate a downloadable report.")


if __name__ == "__main__":
    main()
