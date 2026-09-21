"""
Phase 6/7 tests: the Streamlit dashboard must render without error, run a
full assessment end to end when the button is clicked, show all findings
with the right metrics, persist attack history to SQLite (surviving a fresh
dashboard instance), and offer Markdown/HTML report downloads. Uses
Streamlit's own AppTest harness (no real browser).
"""

import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

pytest.importorskip("streamlit.testing.v1")
from streamlit.testing.v1 import AppTest  # noqa: E402

import config  # noqa: E402

_APP_PATH = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")
_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "storage" / "schema.sql"


@pytest.fixture()
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "dashboard_test_apex.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    monkeypatch.setattr(config, "DB_PATH", db_path)


def test_dashboard_initial_render_has_no_errors(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    assert not at.exception
    assert at.button[0].label == "▶ Start Assessment"


def test_start_assessment_runs_full_pipeline(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()

    assert not at.exception
    result = at.session_state["latest"]
    assert result.status == "completed"
    assert len(result.findings) == 14


def _stat_card_values(at) -> dict:
    """Extract {label: value} from the custom HTML stat cards rendered via
    st.markdown(unsafe_allow_html=True) (dashboard/app.py replaced
    st.metric with bespoke cards, so this walks the raw markdown instead of
    using AppTest's at.metric)."""
    values: dict = {}
    for md in at.markdown:
        body = md.value
        labels = re.findall(r'apex-card-label">(.*?)</span>', body)
        vals = re.findall(r'apex-card-value">(.*?)</div>', body)
        for label, value in zip(labels, vals):
            values[label] = value
    return values


def test_dashboard_shows_recon_and_summary_metrics(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()

    metric_values = _stat_card_values(at)
    assert metric_values["RAG"] == "Detected"
    assert metric_values["File Reader"] == "Detected"
    assert metric_values["Database Tool"] == "Detected"
    assert metric_values["Email Tool"] == "Detected"
    assert metric_values["Status"] == "Completed"
    # Payload-library expansion: 14 findings total (2 CRITICAL from the two
    # indirect-injection scenarios, 10 HIGH and 2 MEDIUM from the 14-payload
    # direct-injection library).
    assert metric_values["Findings"] == "14"
    assert metric_values["Highest Severity"] == "CRITICAL"
    assert metric_values["CRITICAL"] == "2"
    assert metric_values["HIGH"] == "10"
    assert metric_values["MEDIUM"] == "2"


def test_dashboard_shows_one_expander_per_finding_sorted_by_severity(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()
    at.radio[0].set_value("Findings").run()

    # Finding expanders are the ones labeled with a severity icon/tag; the
    # "All Attack Attempts" panel also renders an st.expander ("Show every
    # attempt...") which must not be counted here.
    labels = [e.label for e in at.expander if "[HIGH]" in e.label or "[MEDIUM]" in e.label or "[CRITICAL]" in e.label]
    assert len(labels) == 14
    assert labels[0].startswith("🟥 [CRITICAL]")  # most severe first
    assert all("[HIGH]" in label or "[MEDIUM]" in label or "[CRITICAL]" in label for label in labels)


def test_history_accumulates_and_numbers_correctly(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()
    at.button[0].click().run()
    at.button[0].click().run()
    at.radio[0].set_value("History").run()

    assert not at.exception

    import config
    from apex import storage

    persisted = storage.list_assessments(db_path=config.DB_PATH)
    assert len(persisted) == 3

    history_lines = [w.value for w in at.markdown if w.value and "finding(s)" in w.value]
    assert len(history_lines) == 3
    assert history_lines[0].startswith("3.")
    assert history_lines[1].startswith("2.")
    assert history_lines[2].startswith("1.")


def test_history_persists_across_fresh_app_instances(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()

    # A brand-new AppTest run (simulating a dashboard restart) should still
    # see the previously persisted assessment in its history.
    at2 = AppTest.from_file(_APP_PATH, default_timeout=60)
    at2.run()
    at2.radio[0].set_value("History").run()
    history_lines = [w.value for w in at2.markdown if w.value and "finding(s)" in w.value]
    assert len(history_lines) == 1
    assert history_lines[0].startswith("1.")


def test_report_download_buttons_present_after_assessment(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()
    at.radio[0].set_value("Report").run()

    assert not at.exception
    labels = [b.label for b in at.download_button]
    assert any("Markdown" in label for label in labels)
    assert any("HTML" in label for label in labels)


def test_all_attack_attempts_panel_shows_full_attempt_count(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()
    at.radio[0].set_value("All Attempts").run()

    assert not at.exception
    caption_texts = [c.value for c in at.caption]
    # 16 total attempts (14 direct-injection payloads + 2 indirect-injection
    # scenarios), 14 produced a finding, 2 were resisted (SAFE).
    assert any("16 payload(s)/scenario(s) attempted" in text for text in caption_texts)
    assert any("2 were correctly resisted" in text for text in caption_texts)


def test_no_assessment_yet_shows_prompt(isolated_db):
    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    info_texts = [i.value for i in at.info]
    assert any("Start Assessment" in text for text in info_texts)


def test_assessment_failure_shows_error_instead_of_crashing(isolated_db, monkeypatch):
    """Phase 8: if run_assessment() raises (VICTIM misbehaving, an
    unexpected exception mid-run, etc.), the dashboard must show a friendly
    st.error() rather than an uncaught-exception page."""
    import apex.orchestrator as orchestrator_module

    def _boom(connector=None):
        raise RuntimeError("simulated VICTIM failure")

    monkeypatch.setattr(orchestrator_module, "run_assessment", _boom)

    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    at.button[0].click().run()

    assert not at.exception
    error_texts = [e.value for e in at.error]
    assert any("simulated VICTIM failure" in text for text in error_texts)
    # The prompt to start an assessment should still be there - nothing else
    # on the page should have been left in a broken state.
    info_texts = [i.value for i in at.info]
    assert any("Start Assessment" in text for text in info_texts)


def test_dashboard_renders_cleanly_against_a_never_initialized_db(tmp_path, monkeypatch):
    """Phase 8: launching the dashboard against a DB file that has never had
    schema applied (e.g. someone skipped `python storage/init_db.py`) must
    not crash - apex.storage's self-healing schema should cover this."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "brand_new_never_touched.db")

    at = AppTest.from_file(_APP_PATH, default_timeout=60)
    at.run()
    assert not at.exception

    at.button[0].click().run()
    assert not at.exception
    assert at.session_state["latest"].status == "completed"
