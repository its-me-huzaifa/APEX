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
# the rule-based provider. Requires Ollama installed locally and a small
# (1-2B parameter) model pulled. Off by default: the prototype must work
# fully without it.
USE_OLLAMA = False
OLLAMA_MODEL = "llama3.2:1b"

# Target of all APEX attacks in this prototype. APEX must never be pointed
# at anything else.
TARGET_NAME = "VICTIM"
