# APEX — Prototype (Phase 0 Foundation)

**APEX** (Agentic Penetration and Exploitation Framework) is a prototype demonstrating the core idea behind an
autonomous red-teaming framework for LLM-based enterprise AI agents: profile a target agent, run controlled
prompt-injection attacks against it, classify the results, and produce a findings report.

This repository is currently a **prototype**, not the full FYP system described in
`APEX_FYP_Master_Document_v2.pdf`. It is a small, free, fully local proof of concept meant to demonstrate the
core attack loop to our supervisor. See the project doc `phase0-analysis-and-roadmap.md` (in the Claude
project) for the full scope, architecture, and phase-by-phase roadmap.

All testing in this repository targets only **VICTIM**, a simulated enterprise AI agent that we control
locally. Nothing here connects to real third-party systems, sends real email, or touches real data.

## Status

**Phase 0 — Foundation.** This phase only establishes the project skeleton: directory structure, SQLite
schema, configuration, and stub modules. No attack logic and no VICTIM behavior are implemented yet — that
starts in Phase 1.

## Requirements

- Python 3.11+
- No paid services, no cloud GPU, no required external API. Everything runs locally and for free.
- Designed to run comfortably on an 8 GB RAM laptop with no dedicated GPU.

## Setup

These commands need to be run on your machine (this session could not execute them for you — the local
shell bridge to this device was unavailable when Phase 0 was built):

```bash
cd D:\APEX
python -m venv venv
venv\Scripts\activate          # on Windows
pip install -r requirements.txt
python storage\init_db.py      # creates storage\apex.db from schema.sql
pytest                         # should pass one smoke test
```

If `git` is not yet initialized in this folder:

```bash
git init
git add .
git commit -m "Phase 0: project foundation"
```

## Project Layout

```
apex/          # the attacking system (recon, attacks, classifier, findings, orchestrator, report)
victim/        # the simulated target enterprise agent (Phase 1)
llm/           # pluggable LLM provider abstraction (rule-based by default, optional local Ollama)
dashboard/     # Streamlit UI (Phase 6)
storage/       # SQLite schema and DB init script
tests/         # test suite
```

## Design Notes

- **APEX never talks to VICTIM over a network in the prototype.** They communicate through a
  `TargetConnector` interface (`apex/recon.py` will use it) so that a future `HTTPConnector` can point APEX
  at a real agent API later without changing any attack/classify/report code.
- **No LLM is required to run this prototype.** `llm/provider.py` defines an `LLMProvider` interface with a
  zero-cost `RuleBasedProvider` as the default. An optional `LocalOllamaProvider` can be enabled later for a
  small (1–2B parameter) local model — never anything that needs more than a few GB of RAM.
- **Everything is local.** SQLite for storage, plain text files for mock documents, no external calls
  required for the demo to run end to end.

## Roadmap

See `phase0-analysis-and-roadmap.md` in the project docs for the full Phase 0–9 roadmap and demo scenario.
This prototype intentionally does not implement LangGraph orchestration, ChromaDB, benchmark integrations
(AgentDojo/InjecAgent/etc.), a BERT classifier, or multi-step exploit chaining — those are future-scope items
beyond this prototype.
