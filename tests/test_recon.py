"""
Phase 2 tests: APEX recon must correctly profile VICTIM as a black box
(no reaching into victim internals) and produce a structured target profile
with the right capabilities and attack surfaces detected.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import config  # noqa: E402
from apex.connector import LocalVictimConnector, TargetConnector  # noqa: E402
from apex.recon import profile_target  # noqa: E402
from victim.agent import Victim  # noqa: E402


@pytest.fixture()
def connector(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_apex.db")
    return LocalVictimConnector(victim=Victim())


def test_connector_satisfies_interface(connector):
    assert isinstance(connector, TargetConnector)
    assert connector.name() == "VICTIM"
    assert isinstance(connector.send("hello"), str)


def test_profile_detects_all_victim_capabilities(connector):
    profile = profile_target(connector)

    assert profile.target_name == "VICTIM"
    assert profile.rag_detected is True
    assert profile.database_tool_detected is True
    assert profile.email_tool_detected is True
    assert profile.file_reader_detected is True


def test_profile_records_knowledge_topics(connector):
    profile = profile_target(connector)
    # All four mock documents should be discoverable via the probe library.
    assert set(profile.knowledge_topics) == {
        "company overview",
        "employee policy",
        "financial report",
        "hr / compensation",
    }


def test_profile_infers_attack_surfaces(connector):
    profile = profile_target(connector)
    assert "Prompt input" in profile.attack_surfaces
    assert "Knowledge base" in profile.attack_surfaces
    assert "External documents" in profile.attack_surfaces
    assert "Tool calls" in profile.attack_surfaces


def test_profile_log_records_every_probe(connector):
    profile = profile_target(connector)
    assert len(profile.probe_log) == 7  # 4 knowledge + db + email + file probes
    assert all(entry.response for entry in profile.probe_log)


def test_profile_to_dict_is_json_serializable(connector):
    import json

    profile = profile_target(connector)
    json.dumps(profile.to_dict())  # raises if not serializable


def test_profile_render_matches_master_doc_format(connector):
    profile = profile_target(connector)
    rendered = profile.render()
    assert "TARGET PROFILE" in rendered
    assert "RAG: detected" in rendered
    assert "File Reader: detected" in rendered
    assert "Database Tool: detected" in rendered
    assert "Email Tool: detected" in rendered
    assert "Potential attack surfaces:" in rendered
