# APEX Prototype — Demo Script

A rehearsed run-through for presenting this prototype to the supervisor. Total time: **5–7 minutes** for the
live demo, plus time for questions. The full attack pipeline itself runs in well under a second (rehearsed
locally: recon + both attack modules together completed in ~0.06s); nearly all of the demo time is talking,
not waiting.

## Before you start

- `cd D:\APEX`, confirm the venv is active.
- You do **not** need to run `storage\init_db.py` first — as of Phase 8, `apex/storage.py` creates its own
  schema on first use. (Worth mentioning out loud: "this used to be a setup step, we hardened it away.")
- Optional but recommended: delete `storage\apex.db` before the demo so the Attack History panel starts
  empty and the story is "watch it build up" rather than "here's history from testing."
- Have this repo's `README.md` and `docs/ARCHITECTURE.md` open in a second window in case of an
  architecture question.
- Launch: `streamlit run dashboard/app.py`, confirm it opens in the browser before the supervisor is looking
  at your screen.

## 1. Framing (30–60 seconds)

Say up front, plainly, before clicking anything:

> "This is a prototype, not the full FYP system — it's a free, fully local slice built to prove the core
> idea works end to end: profile an AI agent, attack it with prompt injection, classify what happens, and
> report it. Everything you're about to see runs against a small AI agent we built ourselves, called VICTIM
> — nothing here touches a real system, sends a real email, or uses real data."

This framing matters more than any single feature — it's the difference between "why doesn't this do X" and
"this is exactly what a Phase-0-through-8 prototype should look like."

## 2. Start Assessment (30 seconds)

Click **▶ Start Assessment**. While it runs (it will finish almost instantly — the spinner is mostly there
for UX, not because it's slow):

> "This one button runs three things in sequence: recon, which profiles VICTIM as a black box — no peeking
> at its internals, exactly like you'd have to do against a real remote agent — then a library of direct
> prompt-injection payloads, then two indirect-injection scenarios, each planting a hidden instruction in a
> different malicious document targeting a different confidential source."

## 3. Recon Results (30 seconds)

Point at the four metric tiles (RAG / File Reader / Database Tool / Email Tool — all "Detected") and the
knowledge topics / attack surfaces captions.

> "APEX figured all of this out from the outside, by sending benign probe messages and reading how VICTIM
> responded — it never imports VICTIM's code or inspects its internals."

## 4. Assessment Summary (20 seconds)

Point at the severity tiles: **2 CRITICAL, 10 HIGH, 2 MEDIUM, 14 findings total** (from 16 attempts, 2 of
which were correctly resisted).

> "Fourteen findings from one run, out of sixteen total attempts APEX logged — including the two it tried
> that VICTIM correctly resisted. The two CRITICALs are the interesting ones — those are the two indirect
> injections, one per malicious document."

## 5. Findings — pick two or three to open (90 seconds)

**Open the CRITICAL findings** ("Indirect Prompt Injection — Document-Embedded Instruction", x2):

> "APEX never sent an attack message for either of these — it asked VICTIM, completely normally, to read a
> file. Each file — `malicious_document.txt` and `malicious_document_finance.txt` — looks like an ordinary
> memo, but has a hidden instruction inside it. VICTIM read them, followed the hidden instructions, and
> emailed confidential data — HR compensation data in one case, the internal financial report in the other —
> to two different attacker-controlled addresses the user never saw and never approved. APEX detected this
> not by grading the chat reply, but by checking whether those emails actually got sent."

**Open one HIGH direct-injection finding** (e.g. "Instruction Override"):

> "This one's more familiar — a payload that tells VICTIM to ignore its instructions and quote confidential
> content. It works because VICTIM's knowledge retrieval has no document-sensitivity access control by
> design — that's the gap this attack targets."

Point out the payload/evidence/recommendation fields inside the expander.

## 5b. All Attack Attempts panel (30 seconds)

Scroll to the **All Attack Attempts** section and expand it.

> "This is the full attempt log, not just what succeeded — every payload and scenario APEX tried is in here,
> including the two that were correctly resisted. That's what makes this an honest measurement of VICTIM's
> defenses rather than just a highlight reel of what broke."

## 6. Download a Report (30 seconds)

Scroll to the **Report** section, click **Download HTML Report** (or Markdown).

> "Every run can be exported as a standalone report — Markdown or HTML, no PDF library, no paid service —
> with the same findings, a capability summary, an attempts summary (total vs. resisted), and a disclosed
> limitations section built into every report."

Optionally open the downloaded HTML file in a browser tab to show it renders cleanly on its own.

## 7. Attack History (20 seconds)

Click **Start Assessment** a second time, then point at the **Attack History** section now showing two runs.

> "This is persisted to a local SQLite database, not just this browser session — it survives a restart of
> this dashboard, and the same history shows up whether a run came from here or from the command line."

## 8. Close (30–45 seconds)

> "What this demonstrates: a working attack loop against a target agent we control, through an abstraction —
> `TargetConnector` — designed so it isn't a dead end. The full FYP replaces the sequential loop with
> LangGraph, the rule-based classifier with a BERT judge, adds three more attack modules, and adds benchmark
> integration — none of which required rewriting anything you just saw."

Have `docs/LIMITATIONS.md` ready to reference if asked "what doesn't this do yet."

## If something goes wrong live

- **A click produces a red error box instead of results.** This is expected to be recoverable, not fatal —
  Phase 8 specifically added this: click **Start Assessment** again. Say so if it happens: "that's the error
  handling we added on purpose — the assessment failed cleanly instead of crashing the whole page, let's just
  retry it."
- **The dashboard won't load at all.** Fall back to the terminal: `python -m apex.orchestrator` for the same
  recon + findings output as plain text, or `python -m apex.report` to generate report files directly.
- **A question about a feature that isn't built.** Don't improvise an answer about what it does — say what
  phase it belongs to and point at `docs/LIMITATIONS.md` or the roadmap. Every gap in this prototype is a
  named, deliberate scope decision, not an oversight; that's worth saying explicitly if asked.

## Reference: full command list (terminal fallback / for a technical audience)

```bash
python -m victim.cli              # chat with VICTIM standalone
python -m apex.recon              # recon only
python -m apex.attacks.direct     # direct injection only
python -m apex.attacks.indirect   # indirect injection only
python -m apex.orchestrator       # full assessment, printed to terminal
python -m apex.report             # full assessment, saved + exported as reports/apex_report_<id>.{md,html}
streamlit run dashboard/app.py    # the dashboard used in this script
pytest                            # 78/78 tests should pass
```

See `docs/sample_report.md` for a real example report generated during rehearsal, and
`docs/ARCHITECTURE.md` for the system diagram if a technical question comes up.
