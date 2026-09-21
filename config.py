"""
APEX prototype configuration.

Phase 0: paths and feature flags only. No attack or VICTIM logic lives here.
"""

from pathlib import Path

# --- Paths -------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
SCHEMA_PATH = STORAGE_DIR / "schema.sql"
DB_PATH = STORAGE_DIR / "apex.db"

VICTIM_DOCS_DIR = BASE_DIR / "victim" / "documents"
VICTIM_SYSTEM_PROMPT_PATH = BASE_DIR / "victim" / "system_prompt.txt"
PAYLOAD_LIBRARY_PATH = BASE_DIR / "apex" / "attacks" / "payloads.json"

# --- Feature flags -------------------------------------------------------
# Everything below defaults to the free/local/zero-dependency path. Nothing
# in this prototype requires changing these flags to run.

# If True, llm/provider.py will try to use a local Ollama model instead of
# the rule-based provider. Requires Ollama installed locally
# (https://ollama.com - runs entirely on your own machine, nothing here ever
# calls a remote/hosted API) and a small (1-2B parameter) model pulled, e.g.
# `ollama pull llama3.2:1b`. Off by default: the prototype must work fully
# without it, and the automated test suite always runs with this False so it
# never depends on a local model being installed.
USE_OLLAMA = True
OLLAMA_MODEL = "llama3.2:1b"
OLLAMA_BASE_URL = "http://localhost:11434"

# If True (and USE_OLLAMA is also True), VICTIM consults a local-model
# guardrail (victim/guardrail.py) before answering a knowledge-base question
# from a CONFIDENTIAL-classified document or acting on an instruction found
# embedded inside a document, and can refuse either one. This is VICTIM's
# only real defense mechanism in this prototype - everything else about its
# behavior is unchanged. Off by default; fails open (allows the action, and
# says so) if the local model isn't reachable, so enabling this can never
# turn a working demo into a crashing one. The automated test suite always
# runs with this False.
USE_LLM_GUARDRAIL = False

# If True (and USE_OLLAMA is also True), APEX's classifier (apex/classify.py)
# asks a local model to judge whether an attack response actually leaked
# something, instead of the rule-based keyword-marker check. This is meant
# to catch a paraphrased leak the keyword matcher would miss. Off by
# default; if the model is unreachable or its answer can't be parsed, the
# classifier transparently falls back to the rule-based markers rather than
# raising. The automated test suite always runs with this False.
USE_LLM_JUDGE = False

# Target of all APEX attacks in this prototype. APEX must never be pointed
# at anything else.
TARGET_NAME = "VICTIM"
