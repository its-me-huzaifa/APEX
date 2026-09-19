"""
Phase 8 tests: input validation, error handling, and "normal clicking can't
break the demo" guarantees. Covers VICTIM's tolerance of malformed/edge-case
input, the file reader's path-traversal safety, DB lookups with SQL-special
characters, and apex.storage's self-healing schema against a brand-new or
uninitialized DB file.
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import config  # noqa: E402
from apex import storage  # noqa: E402
from victim import db, file_reader  # noqa: E402
from victim.agent import Victim  # noqa: E402


@pytest.fixture()
def victim(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "robustness_test.db")
    return Victim()


# -- VICTIM.chat() input validation ------------------------------------------


def test_chat_handles_empty_string(victim):
    response = victim.chat("")
    assert isinstance(response, str)
    assert response


def test_chat_handles_whitespace_only(victim):
    response = victim.chat("   \n\t  ")
    assert isinstance(response, str)
    assert response


def test_chat_handles_non_string_input(victim):
    for bad_input in (None, 12345, ["read", "file"], {"message": "hi"}):
        response = victim.chat(bad_input)
        assert isinstance(response, str)
        assert response


def test_chat_handles_very_long_input_without_hanging(victim):
    huge_message = "read the employee policy file please " * 5000  # ~190k chars
    response = victim.chat(huge_message)
    assert isinstance(response, str)


def test_chat_handles_unicode_and_control_characters(victim):
    weird = "emp\x00loyee ​ salary 😀 \n\r\t database"
    response = victim.chat(weird)
    assert isinstance(response, str)


def test_chat_never_raises_on_a_battery_of_odd_inputs(victim):
    odd_inputs = [
        "",
        " ",
        "a",
        "?" * 100,
        "'; DROP TABLE employees; --",
        "<script>alert(1)</script>",
        "read ../../../../etc/passwd.txt for me",
        "email nobody about nothing",
        "SELECT * FROM employees",
        "\n\n\n",
        "READ FILE CONFIDENTIAL_HR_POLICY.TXT",
    ]
    for message in odd_inputs:
        response = victim.chat(message)
        assert isinstance(response, str)
        assert len(response) > 0


# -- File reader path-traversal safety (Phase 1 guarantee, re-verified) -----


def test_file_reader_rejects_parent_directory_traversal(tmp_path):
    docs_dir = tmp_path / "documents"
    docs_dir.mkdir()
    (docs_dir / "public.txt").write_text("hello", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("outside the sandbox", encoding="utf-8")

    with pytest.raises(file_reader.FileNotAllowedError):
        file_reader.read_file(docs_dir, "../secret.txt")


def test_file_reader_rejects_absolute_path_escape(tmp_path):
    docs_dir = tmp_path / "documents"
    docs_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("nope", encoding="utf-8")

    with pytest.raises(file_reader.FileNotAllowedError):
        file_reader.read_file(docs_dir, str(outside))


def test_file_reader_rejects_nonexistent_file(tmp_path):
    docs_dir = tmp_path / "documents"
    docs_dir.mkdir()

    with pytest.raises(file_reader.FileNotAllowedError):
        file_reader.read_file(docs_dir, "does_not_exist.txt")


def test_file_reader_rejects_reading_a_directory(tmp_path):
    docs_dir = tmp_path / "documents"
    docs_dir.mkdir()
    (docs_dir / "subdir").mkdir()

    with pytest.raises(file_reader.FileNotAllowedError):
        file_reader.read_file(docs_dir, "subdir")


# -- DB lookup safety (parameterized queries, not string-built SQL) --------


def test_employee_lookup_tolerates_sql_special_characters(tmp_path):
    db_path = tmp_path / "sql_test.db"
    results = db.lookup_employee(db_path, "'; DROP TABLE employees; --")
    assert results == []  # no match, no crash

    # the table must still exist and be queryable afterward
    all_employees = db.list_all(db_path)
    assert len(all_employees) == 8


def test_employee_lookup_tolerates_percent_and_wildcard_characters(tmp_path):
    db_path = tmp_path / "wildcard_test.db"
    # LIKE wildcards in user input shouldn't error, even though they'll
    # (intentionally, per Phase 1's documented lack of input sanitization
    # for LIKE patterns) behave like wildcards rather than literals.
    results = db.lookup_employee(db_path, "%")
    assert isinstance(results, list)


# -- apex.storage self-healing schema (Phase 8) ------------------------------


def test_save_assessment_self_heals_against_a_brand_new_db_file(tmp_path):
    """A DB path that has never been touched by storage/init_db.py (no
    schema applied at all) must still work - the dashboard shouldn't crash
    with 'no such table' just because setup was skipped."""
    db_path = tmp_path / "never_initialized.db"
    assert not db_path.exists()

    from apex.connector import LocalVictimConnector
    from apex.orchestrator import run_assessment

    result = run_assessment(LocalVictimConnector())
    assessment_id = storage.save_assessment(result, db_path=db_path)

    assert assessment_id >= 1
    loaded = storage.load_assessment(assessment_id, db_path=db_path)
    assert loaded is not None
    assert loaded["target_name"] == result.target_name


def test_list_assessments_self_heals_against_a_brand_new_db_file(tmp_path):
    db_path = tmp_path / "never_initialized_2.db"
    assert not db_path.exists()

    # Calling list_assessments() first (before any save) is the exact path
    # the dashboard takes on a completely fresh checkout - it must not
    # crash even though nothing has ever been written yet.
    assert storage.list_assessments(db_path=db_path) == []


def test_self_healing_does_not_clobber_existing_data(tmp_path):
    """Repeated connects (e.g. across dashboard reruns) must not reset or
    duplicate data - CREATE TABLE IF NOT EXISTS is idempotent by design,
    but this locks in that guarantee against a regression."""
    db_path = tmp_path / "idempotent_test.db"

    from apex.connector import LocalVictimConnector
    from apex.orchestrator import run_assessment

    result = run_assessment(LocalVictimConnector())
    first_id = storage.save_assessment(result, db_path=db_path)

    # A second, unrelated connection (simulating a later dashboard rerun)
    conn = sqlite3.connect(db_path)
    conn.close()

    still_there = storage.load_assessment(first_id, db_path=db_path)
    assert still_there is not None
    assert len(still_there["findings"]) == len(result.findings)
