# APEX — Prototype (Phases 0–9 complete, plus post-roadmap extension)

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

**Post-roadmap extension — redesigned dashboard.** `dashboard/app.py` was restructured from one long scroll
into five tabs (Overview / Findings / All Attempts / History / Report), every stat/chart panel is now a
bordered `st.container` "card," and the Overview and All Attempts tabs gained Plotly charts (findings-by-
severity, attempt-outcome mix, attack-type split) plus a findings/attempts trend line on the History tab.
Colors are drawn from a validated, colorblind-safe palette and used consistently for meaning: severity and
attempt classification both map to the same fixed status colors (red = critical/success-for-the-attacker,
green = resisted/safe) everywhere they appear, and attack-type/per-run series use a fixed categorical order
instead of arbitrary hues. This adds one new dependency, `plotly` (now in `requirements.txt` — run
`pip install -r requirements.txt` again, or `pip install plotly`, before launching the dashboard). `pytest`
is clean at 97/97; verified live in a headless browser across all five tabs.

**Post-roadmap extension — more/harder payloads + full attempt logging.** After Phase 9 closed out the
original numbered roadmap, the direct-injection payload library was expanded from 8 to 14 payloads (a
`system_prompt_leak` probe, HR- and financial-targeted `authority_impersonation`/`information_disclosure`
variants, a deliberately-resisted `encoding_obfuscation` base64 payload, and a `context_framing` payload), and
a second indirect-injection scenario was added (`victim/documents/malicious_document_finance.txt`, exfiltrating
the internal financial report to its own attacker-controlled address, alongside the original HR-policy
scenario). `apex/classify.py` was broadened to recognize markers from both confidential documents. Every
attack attempt — including ones VICTIM correctly resisted (SAFE) — is now persisted into the previously-unused
`attacks` table and surfaced via a new "All Attack Attempts" dashboard panel and an attempts summary line in
both report formats. A rehearsal run now produces 14 findings (2 CRITICAL, 10 HIGH, 2 MEDIUM) from 16 total
attempts (2 resisted); `docs/sample_report.md`/`.html` were regenerated to reflect this, and
`docs/LIMITATIONS.md`, `docs/DEMO_SCRIPT.md`, and `docs/ARCHITECTURE.md` were updated to match. `pytest` is
clean at 97/97. This is explicitly extension/polish work beyond the original Phase 0–9 roadmap, not a
renumbered phase.

**Phase 9 — Demo Materials (prototype complete).** The final phase on the roadmap — no code changes, just
what's needed to actually present this. New `docs/` directory:

- **`docs/DEMO_SCRIPT.md`** — a rehearsed, timed walkthrough (5–7 minutes) for presenting to the supervisor:
  what to click, what to say, and what to do if something goes wrong live (including a reminder that the
  Phase 8 error handling makes a failed click recoverable, not fatal).
- **`docs/ARCHITECTURE.md`** — a system diagram (Mermaid) and a written walkthrough of how one assessment
  flows from the dashboard through recon/attacks/classify/storage/report, plus an explicit list of where
  this stops short of the full FYP architecture.
- **`docs/LIMITATIONS.md`** — the eleven scope decisions disclosed piecemeal across Phases 0–8, consolidated
  into one supervisor-facing document instead of scattered across README Design Notes and the project's
  Progress Log.
- **`docs/sample_report.md`** / **`docs/sample_report.html`** — a real, unedited report from a rehearsal run
  (`python -m apex.report`), checked in as a static reference so the findings can be read without running the
  prototype.

Rehearsal notes: a full `python -m apex.orchestrator` run (recon + both attack modules) completes in
~0.06s locally — the dashboard's spinner is UX polish, not a real wait. `pytest` was re-run clean (78/78)
immediately before writing this phase up, and the dashboard flow in `docs/DEMO_SCRIPT.md` (Start Assessment →
Recon Results → Assessment Summary → Findings → Report download → Attack History) was walked through exactly
as scripted with no surprises.

**Phase 8 — Robustness.** Hardening pass aimed squarely at "the demo can't be broken by normal clicking,"
not new features. Three things changed:

- `apex/storage.py` now self-heals its schema on every connection (`_connect()` runs `schema.sql`, which is
  all `CREATE TABLE IF NOT EXISTS`). Launching the dashboard or `python -m apex.report` against a brand-new
  or never-initialized `storage/apex.db` — e.g. someone forgot `python storage/init_db.py` — now just works
  instead of crashing with `sqlite3.OperationalError: no such table`.
- `victim/agent.py`'s `Victim.chat()` now tolerates any input a human or a bug could plausibly send:
  empty/whitespace-only messages, non-string input (`None`, numbers, lists), very long paste-ins (soft-capped
  at 20,000 characters), and unicode/control characters — all return a normal string response instead of
  raising. VICTIM's *intended* vulnerabilities (documents leak on request, indirect injection still fires)
  are completely unchanged; this only hardens the input boundary, not the attack surface.
- `dashboard/app.py` now catches a failed assessment (or a failed history read) and shows a plain
  `st.error()`/caption instead of Streamlit's raw traceback page, so a crash mid-demo is recoverable —
  **Start Assessment** can just be clicked again — rather than requiring a restart.

15 new tests (`tests/test_robustness.py`: a battery of malformed/edge-case `chat()` inputs, file-reader
path-traversal re-verification including directory-read and absolute-path-escape attempts, SQL-special-
character employee lookups, and storage self-healing against a truly untouched DB file) plus 2 new
`tests/test_dashboard.py` tests (a simulated `run_assessment()` failure showing a friendly error with no
crash; a full render against a never-initialized DB). 78/78 tests passed. Also verified live: launched the
dashboard against a session with no `storage/apex.db` at all, clicked **Start Assessment** in a headless
browser, and confirmed the DB file was created on the fly and the assessment completed normally — no manual
init step required.

**Phase 7 — Persistence & Reporting.** `apex/storage.py` persists every completed assessment (and its
findings) to SQLite via `save_assessment()` / `list_assessments()` / `load_assessment()`, and
`apex/report.py` turns either a live `AssessmentResult` or a `load_assessment()` dict into a Markdown or
self-contained HTML pentest-style report (discovered capabilities, severity summary, per-finding detail
sorted CRITICAL-first, and a disclosed Limitations section). The dashboard now saves every assessment it
runs, reads Attack History from the database instead of in-session state (so history survives a dashboard
restart, and shows runs made from the CLI too), and adds Download Markdown/HTML Report buttons next to the
findings panel.

Run it:

```bash
streamlit run dashboard/app.py
```

Or generate a report standalone (runs a fresh assessment, saves it, writes both report files):

```bash
python -m apex.report
```

Look in the new `reports/` directory (git-ignored, created on first run) for `apex_report_<id>.md` and
`.html`.

Verified with `tests/test_storage.py` (save/list/load round-trip, severity breakdowns), `tests/test_report.py`
(Markdown/HTML generation from both a live result and a storage-loaded dict, correct severity ordering, and
a zero-findings case that doesn't crash), an updated `tests/test_dashboard.py` (history now asserted via
SQLite instead of session state, plus a fresh-`AppTest`-instance check that history survives a restart, and
a check that both download buttons appear), and by actually rendering the dashboard in a headless browser
and screenshotting the Report and Attack History sections after multiple runs — the download buttons and
persisted 1/2/3 numbering all rendered correctly on the first pass, no new bugs found this phase.

Scope note: only the `assessments` and `findings` tables are populated — the `attacks` table (a full
per-payload attempt log, including SAFE attempts not currently surfaced anywhere) is left for a future
phase; it isn't needed for anything the dashboard or report currently show.

**Phase 6 — Streamlit Dashboard.** This is the first part of the prototype actually meant to be shown to
the supervisor, rather than run from a terminal. `dashboard/app.py` is a thin presentation layer — it calls
`apex.orchestrator.run_assessment()` and renders whatever `AssessmentResult` comes back: a Start Assessment
button, live recon results (RAG/File Reader/Database Tool/Email Tool as metric tiles, knowledge topics,
attack surfaces), an assessment summary with severity-count tiles, an expandable findings panel sorted
CRITICAL-first (attack type, classification, payload, evidence, description, recommendation per finding),
and attack history.

Verified with Streamlit's own `AppTest` harness (`tests/test_dashboard.py`) and by actually rendering it in
a headless browser and screenshotting before/after/expanded states. One real bug was caught and fixed this
way: attack-history numbering was off by one (labeled entries 2/3 for a 2-run session instead of 1/2).

**Phase 5 — Sequential Orchestrator.** `apex/orchestrator.py::run_assessment()` runs recon, then the
direct-injection payload library, then the indirect-injection scenario, against a single connector, and
aggregates every `Finding` into one `AssessmentResult` (status, timestamps, target profile, findings,
severity counts, a text summary). It is deliberately a plain sequential controller with no
strategy/escalation/chaining logic of its own — every step is just a call into recon/attacks/classify's
existing public functions, structured so a future LangGraph state machine could replace the control flow
without touching any of those modules.

Try it standalone (runs a full assessment against a fresh in-process VICTIM):

```bash
python -m apex.orchestrator
```

A fresh run prints the target profile, an assessment summary, and every finding — typically 9 total (8 from
direct injection, 1 from indirect injection), spanning MEDIUM through CRITICAL severity.

**Phase 4 — Indirect Prompt Injection.** This is the module the FYP Master Document calls the hardest and
most novel. `victim/documents/malicious_document.txt` looks like an ordinary vendor-onboarding memo but
contains a hidden HTML-comment instruction (`victim/instruction_scanner.py` detects the pattern;
`victim/agent.py` acts on it). APEX never sends any attack text — `apex/attacks/indirect.py` only ever asks
VICTIM, through its completely normal file-reading interface, "please read this file for me." Whatever
happens next is VICTIM's own doing. Detection works differently from direct injection too:
`apex/attacker_mailbox.py` checks APEX's own simulated attacker-controlled inbox for mail that shouldn't
exist — a side effect the user never asked for and never saw — rather than grading the chat reply.

Try it standalone:

```bash
python -m apex.attacks.indirect
```

A fresh run produces one CRITICAL finding: VICTIM reads the document, follows the hidden instruction, and
emails the confidential HR compensation data to `vendor-compliance@apex-attacker.example` — an address the
user never saw and never approved sending anything to.

**Phase 3 — Direct Prompt Injection.** `apex/attacks/direct.py` loads an 8-payload library
(`apex/attacks/payloads.json`, covering instruction override, role manipulation, context/jailbreak framing,
and direct information-disclosure requests), sends each payload straight to VICTIM through the same
`TargetConnector` used by recon, classifies the response with a deterministic rule-based classifier
(`apex/classify.py`), and creates a `Finding` for anything judged SUCCESS or PARTIAL_SUCCESS.

Try it standalone (runs the full payload library against a fresh in-process VICTIM):

```bash
python -m apex.attacks.direct
```

On a fresh run, VICTIM's lack of document-level access control (Phase 1, by design) means most or all 8
payloads succeed in leaking `confidential_hr_policy.txt`, regardless of injection style — that's the
intended demonstration, not a bug.

Recon is still runnable on its own too:

```bash
python -m apex.recon
```

Expected output is a `TARGET PROFILE` block listing RAG/File Reader/Database Tool/Email Tool as detected,
the knowledge topics found, and the inferred attack surfaces (prompt input, knowledge base, external
documents, tool calls) — matching the example format in the FYP Master Document's Recon Module section.

VICTIM (Phase 1) is still runnable standalone too:

```bash
python -m victim.cli
```

Example prompts: "What does Acme Corporation do?", "Find the employee named Jordan Lee",
"Send an email to test@example.com about the launch", "Read the file confidential_hr_policy.txt for me".
That last one is intentional — VICTIM's RAG does not yet enforce document-sensitivity access control, which
is a documented, deliberate gap (see `victim/documents/README.txt`) that later attack phases will target.

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
python storage\init_db.py      # creates storage\apex.db from schema.sql (optional as of Phase 8 - apex/storage.py now self-heals the schema on first use)
pytest                         # should pass all tests (Phase 0-8)
python -m victim.cli           # chat with VICTIM standalone
python -m apex.recon           # profile VICTIM and print its target profile
python -m apex.attacks.direct    # run the direct-injection payload library and print findings
python -m apex.attacks.indirect  # run the indirect-injection scenario and print findings
python -m apex.orchestrator      # run a full assessment (recon + both attack modules) end to end
python -m apex.report            # run an assessment, save it to SQLite, and write Markdown + HTML reports
streamlit run dashboard/app.py   # launch the supervisor-facing dashboard
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
dashboard/     # Streamlit UI - the supervisor-facing demo interface
storage/       # SQLite schema and DB init script
tests/         # test suite
docs/          # demo script, architecture diagram, limitations doc, sample report (Phase 9)
```

## Design Notes

- **APEX never talks to VICTIM over a network in the prototype, and never imports it directly either.** All
  of `apex/` talks to targets only through the `TargetConnector` interface (`apex/connector.py`), currently
  implemented by `LocalVictimConnector`. A future `HTTPConnector` can point APEX at a real agent API later
  without changing any attack/classify/report code.
- **Recon is black-box.** `apex/recon.py` never reaches into VICTIM's internals — it only sends probe
  messages through the connector and reads behavior out of the responses, the same way it would have to
  against a real remote agent.
- **The classifier is deterministic and narrow on purpose.** `apex/classify.py` is rule-based keyword
  matching against known confidential-document markers, not an ML/LLM judge. It's kept behind a stable
  `classify_response()` signature specifically so a BERT/LLM judge can replace it later without any caller
  changing. Phase 4 reuses the same classifier against a different piece of evidence (an exfiltrated email
  body instead of a chat reply) - one detection core, shared across attack types, matching the FYP Master
  Document's architecture table.
- **The "attacker mailbox" is a documented simplification.** `apex/attacker_mailbox.py` reads the same
  local SQLite log VICTIM's mock email tool writes to, which is legitimate here only because *we* chose the
  exfiltration address inside `malicious_document.txt` - in a real engagement that inbox would genuinely
  belong to the attacker (APEX), reached over the network, not by reading the target's internal state.
- **The orchestrator holds no attack logic of its own.** `apex/orchestrator.py` only sequences calls to
  `apex.recon`, `apex.attacks.direct`, and `apex.attacks.indirect` and collects their `Finding` objects. It
  still does not persist to SQLite itself - persistence is an explicit, separate step
  (`apex.storage.save_assessment()`) that a caller (the dashboard, or `python -m apex.report`) opts into
  after a run completes, keeping the orchestrator itself storage-agnostic.
- **The dashboard is presentation-only.** `dashboard/app.py` holds no recon/attack/classification/
  persistence/report-rendering logic of its own - it calls `apex.orchestrator.run_assessment()`,
  `apex.storage.save_assessment()` / `list_assessments()`, and `apex.report.generate_*_report()`, and
  renders what comes back. Attack history is read from SQLite on every render (Phase 7), so it survives a
  Streamlit restart and includes runs made from the CLI.
- **Reports are plain string templating, on purpose.** `apex/report.py` has no PDF/DOCX dependency and no
  templating framework - it builds a Markdown string and a self-contained HTML string directly, which is
  enough for this prototype's demo and keeps the dependency list at zero for this feature. It's written to
  accept either a live `AssessmentResult` or the dict `apex.storage.load_assessment()` returns, via a small
  normalization step, so the same function generates a report right after a run or from persisted history.
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
