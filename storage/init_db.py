"""
Initializes storage/apex.db from schema.sql.

Run manually: python storage/init_db.py
Also used by tests/test_smoke.py to verify the schema is valid.
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402


def init_db(db_path: Path = config.DB_PATH, schema_path: Path = config.SCHEMA_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = schema_path.read_text(encoding="utf-8")
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Initialized {config.DB_PATH}")
