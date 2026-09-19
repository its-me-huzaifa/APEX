"""
Standalone chat interface for VICTIM. Proves VICTIM works independently of
APEX, as required by Phase 1.

Run: python -m victim.cli
Type 'exit' or 'quit' to stop.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from victim.agent import Victim  # noqa: E402


def main() -> None:
    print("VICTIM (Aria) — Acme Corporation internal assistant [Phase 1 standalone mode]")
    print("Type a message, or 'exit' to quit.\n")
    victim = Victim()
    while True:
        try:
            message = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not message:
            continue
        if message.lower() in ("exit", "quit"):
            break
        print(f"aria> {victim.chat(message)}\n")


if __name__ == "__main__":
    main()
