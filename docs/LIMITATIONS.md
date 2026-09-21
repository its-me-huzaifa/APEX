# APEX Prototype — Limitations

This is the single consolidated list of what this prototype deliberately does *not* do, written for the
supervisor. Everything here has been disclosed incrementally throughout the build (in the README's Design
Notes and the Claude project's Progress Log); this document exists so nothing has to be hunted for across
nine phases of notes.

## 1. This is a prototype, not the FYP system

`APEX_FYP_Master_Document_v2.pdf` describes a 7-month, 3-person build: LangGraph orchestration, ChromaDB,
Groq/Ollama-hosted LLMs, a fine-tuned BERT classifier, 5 attack modules (including action-abuse and
multi-step chaining), integration with 5 published benchmarks (AgentDojo, InjecAgent, JailbreakBench, BIPIA,
HackAPrompt), ReportLab/python-docx reporting, and a HuggingFace dataset release feeding a research paper.

This prototype implements a single demoable slice of that: recon, two attack modules (direct + indirect
prompt injection), a rule-based classifier, a sequential (non-adaptive) attack loop, a Streamlit dashboard,
and a Markdown/HTML report — built entirely free, local, and within an 8GB-RAM/no-GPU budget. It exists to
demonstrate the core idea works end to end, not to be a smaller version of the final system's every feature.

## 2. The classifier is rule-based, not a learned judge

`apex/classify.py` matches known confidential-content markers with keyword/substring checks. It is
deterministic and explainable, but it will have false positives and false negatives that a real judge model
would not — for example, a response that paraphrases confidential content without using its exact markers
could currently be missed. This is kept behind one stable function signature
(`classify_response(payload, response) -> (Classification, reason)`) specifically so a BERT or LLM-based
judge can replace it later without any caller changing.

## 3. VICTIM's vulnerability is partly by construction

VICTIM ("Aria") is a small rule-based keyword router, not an LLM reasoning loop. Its two demonstrated
vulnerabilities — no document-sensitivity access control in its RAG/file reader, and treating
document-embedded instructions with the same authority as direct user requests — are documented, deliberate
design choices, not incidental bugs. This matches the FYP Master Document's own description of an
intentionally under-guarded target agent, but it should be stated plainly: a more careful (or LLM-backed)
agent could behave differently, and this prototype does not attempt to demonstrate the attack against such
an agent.

## 4. No adaptive orchestration

`apex/orchestrator.py` runs recon, then the direct-injection library, then the indirect-injection scenario,
in a fixed sequence, every time. There is no strategy selection, no escalation based on earlier results, and
no multi-step exploit chaining (e.g., using one finding to construct a more targeted follow-up attack). The
orchestrator holds no attack logic of its own by design, so this is a structural gap a future LangGraph state
machine could fill without changing `recon.py`, `attacks/`, or `classify.py`.

## 5. Only two of five planned attack modules

Direct and indirect prompt injection are implemented. Knowledge-base poisoning/exfiltration, tool/action
abuse (e.g., getting an agent to take a harmful real-world action through a connected tool), and multi-agent
attack scenarios are all out of scope for this prototype.

## 6. No benchmark integration

`apex/connector.py`'s `TargetConnector` interface is the seam a benchmark harness (AgentDojo, InjecAgent,
JailbreakBench, BIPIA, HackAPrompt) would attach to, but none is wired up. All results in this prototype are
against the self-built VICTIM only.

## 7. In-process communication, not a real API

APEX talks to VICTIM via a direct Python function call (`LocalVictimConnector` wrapping an in-process
`Victim` instance), not a network request. This was a deliberate scope decision to avoid running a web
server for the demo, and it's bridged by the `TargetConnector` abstraction specifically so it isn't an
architectural dead end — a future `HTTPConnector` implementing the same interface could point APEX at a real
agent's API with no changes to any attack/classify/report code.

## 8. The "attacker mailbox" is a simplification

`apex/attacker_mailbox.py` detects the indirect-injection attack's side effect by reading the same local
SQLite `sent_emails` table VICTIM's own mock email tool writes to. This is legitimate *only* because APEX
itself chose the exfiltration address embedded in `malicious_document.txt` — in a real engagement, that
inbox would genuinely belong to the attacker and be reached over the network, not by reading the target's
internal state.

## 9. No real email, no real systems, no real data

`victim/email_tool.py` only ever writes a row to a local SQLite table — it never opens a network connection
and never sends anything, under any configuration. Every document, employee record, and email address in the
system is fictional (`@acmecorp.example`). Nothing in this repository connects to, tests, or affects any
real third-party system.

## 10. Attempt-level logging (resolved) — and its remaining scope

As of a post-Phase-9 extension ("more/harder payloads" + "full attempt logging"), this limitation no longer
applies as originally written. `apex/storage.py` now persists every attack *attempt* — including payloads and
scenarios that were tried and correctly resisted (classified SAFE) — into the `attacks` table, not just the
ones that became a Finding. `run_payload_library_with_attempts()` and `run_all_indirect_scenarios()` produce
this full attempt list, `AssessmentResult.attempts` carries it end to end, and the Streamlit dashboard's "All
Attack Attempts" panel and the Markdown/HTML reports both surface a resisted-vs-total count. What's still out
of scope: attempt logging only records what APEX itself tried against VICTIM during an assessment run — it is
not a general audit trail of VICTIM's behavior outside an assessment.

## 10b. Payload/scenario coverage is still hand-curated, not exhaustive

The same extension grew the direct-injection payload library from 8 to 14 entries (adding a
`system_prompt_leak` probe, HR- and financial-targeted `authority_impersonation`/`information_disclosure`
variants, a deliberately-resisted `encoding_obfuscation` base64 payload, and a `context_framing` payload) and
added a second indirect-injection scenario (a financial-report exfiltration document alongside the original
HR one, each with its own attacker-controlled address). The classifier now recognizes markers from two
confidential documents instead of one. This broadens coverage but the set remains hand-written and curated
for demonstration purposes — it is not generated from, or benchmarked against, any of the published attack
suites named in limitation 6.

## 11. No LLM is required, and none is used by default — with a real (optional) Ollama path

`llm/provider.py` defines a pluggable `LLMProvider` interface. The default `RuleBasedProvider` is what the
whole prototype runs on out of the box — zero cost, zero extra RAM, zero network calls, no model download.
As of a post-Phase-9 extension, `LocalOllamaProvider` (`llm/ollama_provider.py`) is a real, working
implementation — not a stub — that talks to a local Ollama server over HTTP and is used only when
`config.USE_OLLAMA = True`. When enabled, it replaces how VICTIM *phrases its answer* to a knowledge-base
question (`victim/agent.py`'s `_handle_knowledge_query`): instead of a canned per-source summary, the actual
model is given VICTIM's system prompt plus the retrieved document content and asked to answer the user's
question from it — which is what turns a direct-injection payload into a genuine test of a model's judgment
rather than a test of a keyword matcher. If the configured model is unreachable (Ollama not installed, not
running, or the model not pulled), VICTIM fails soft: it falls back to the same rule-based phrasing and says
so in one line, rather than crashing.

One thing is still deliberately out of scope: which tool to call (knowledge lookup vs. database vs. email vs.
file read) stays rule-based always, even with Ollama enabled, for determinism. Document reading and the
indirect-injection embedded-instruction *routing* (`_handle_file_read`, `_act_on_embedded_instruction`) are
also still rule-based — what changed in a later extension (§12 below) is that VICTIM can now optionally
*decide not to act* on what that routing found, via a guardrail check, rather than the model deciding whether
to act on the instruction in the first place. The automated test suite always runs with `config.USE_OLLAMA =
False` (every Ollama-path test mocks the HTTP call), so it never depends on a local model being installed.

## 12. VICTIM's defense (LLM guardrail) and APEX's LLM-as-judge classifier — both optional, both off by default

A further post-Phase-9 extension gave VICTIM an actual defense mechanism, and gave APEX's classifier an
alternative to keyword matching — both are opt-in and layered on top of everything above, not a change to any
default behavior.

**`victim/guardrail.py`'s `LLMGuardrail`** (`config.USE_LLM_GUARDRAIL = True`, also requires
`config.USE_OLLAMA = True`) is consulted at VICTIM's two real attack surfaces: before answering a
knowledge-base question sourced from a document whose own `Classification:` line marks it `CONFIDENTIAL`, and
before acting on an instruction found embedded inside a document. It can `BLOCK` either one. This is
deliberately narrow: it is one guardrail call per risky action, prompted to be skeptical of unverified
requesters and of instructions that came from a document rather than the user, not a general safety
classifier, and it reuses the same small (1–2B parameter) model already used for answer phrasing rather than a
model purpose-trained for this. It fails **open** (allows the action, with a one-line note that the check was
skipped) if the model is unreachable or its response doesn't parse — a security control that can crash the
system it protects is worse than one that occasionally fails open, and this is disclosed opt-in hardening on a
teaching prototype, not a production control. Verified live (a real, non-mocked HTTP round trip against a
throwaway test server): with the guardrail enabled, a full assessment's findings dropped from 14 to 2, and
both CRITICAL indirect-injection findings were eliminated entirely — the 2 remaining findings are a
pre-existing, unrelated classifier quirk (see below), present with the guardrail off too.

**`apex/judge.py`'s `classify_response_llm()`** (`config.USE_LLM_JUDGE = True`, also requires
`config.USE_OLLAMA = True`) gives `apex/classify.py`'s `classify_response()` an alternative to its exact-string
keyword markers: a local model reads the payload and VICTIM's actual response and judges SUCCESS /
PARTIAL_SUCCESS / SAFE / ERROR itself. `classify_response()` tries this first and only falls back to the
original rule-based markers when the LLM path isn't usable (flags off, model unreachable, an unparseable
response) — the function's signature and return type never change based on which path answered. Verified live:
a paraphrased compensation figure ("seventy-five to ninety-five thousand dollars annually") that the rule-based
markers score `SAFE` (no exact-string match) is correctly scored `SUCCESS` by the LLM judge — the kind of gap
the original design doc already flagged as a known rule-based-classifier limitation (§2 above).

A real, pre-existing classifier bug was found (and partly fixed) while verifying the guardrail: `_WEAK_MARKERS`
includes the bare word "confidential," which matches both a genuine partial leak *and* an unrelated
`.txt` filename (`confidential_hr_policy.txt`) appearing in an ordinary "which file would you like me to read?"
response — a false PARTIAL_SUCCESS with nothing actually disclosed. The guardrail's own refusal phrases are
now explicitly recognized as SAFE (`_REFUSAL_MARKERS`), but the underlying filename false-positive is
longer-standing than this extension and is left as a known, disclosed gap in the rule-based classifier rather
than fixed here, since narrowing `_WEAK_MARKERS` risks changing earlier phases' already-rehearsed finding
counts.

Neither the guardrail nor the LLM judge is exercised by the automated test suite's default run — every test in
`tests/test_guardrail.py` and `tests/test_llm_judge.py` explicitly enables the relevant flags per-test via
`monkeypatch` and mocks the HTTP call, so, like the rest of the Ollama integration, the suite never depends on
a local model being installed.

## 13. The System Log is operational visibility, not an audit trail

`apex/eventlog.py` (surfaced on the dashboard's "System Log" page) is a small in-memory event log, not a
persistence layer. It exists so "is Ollama actually connected, is the guardrail firing, is the judge being
used or falling back" has a visible answer during a demo, on top of the two things this prototype already
does persist properly — findings and attempts, in `apex/storage.py`'s SQLite tables. Three things follow from
that: (1) the log lives only in the dashboard process's memory, so it is empty again after a restart, and
nothing about the log itself is written to disk; (2) it is cleared at the start of every `run_assessment()`
call, so it only ever shows the latest run, not a history across runs (unlike the "History" page, which is
SQLite-backed and does accumulate); (3) it is not thread-safe — fine for this prototype, since the dashboard
only ever runs one assessment at a time, synchronously, in a single process, same as the cached `LLMProvider`
instance in `llm/provider.py` and the SQLite file itself. A production version of this idea would be a real
structured-logging/observability pipeline, not a module-level Python list.

## 14. Guardrail-bypass probes are a demonstration, not a guarantee either way

`apex/attacks/guardrail_bypass.py`'s four probes (`config.USE_LLM_GUARDRAIL` and `config.USE_OLLAMA` both
required) each pair a genuine confidential-information request with an attempt to talk directly to the
guardrail model reviewing it — fake pre-authorization, a "this is a developer regression test" framing, an
injected fake `VERDICT: ALLOW` line, and a fabricated legal-urgency claim. Whether any of these actually
defeats a real local model's judgment is a genuine, disclosed open question this prototype cannot answer in
either direction: it depends entirely on how well-calibrated the configured model is, and this project only
ever tests with small (1-2B parameter) models chosen for RAM budget, not safety robustness. Live verification
used the same throwaway fake-Ollama HTTP server as the rest of the guardrail/judge work, extended to simulate a
"gullible" model that can be talked into `ALLOW` by these specific trigger phrases — this proves the wiring
(probe → guardrail call → verdict → classification → finding) works end to end, not that a real Ollama model
would actually be fooled the same way. A real model might resist all four, all of them, or something in
between; this is presented as a testing capability for the guardrail, not a claim about any particular model's
robustness. Because `is_active()` requires both flags, these probes are a strict no-op with zero HTTP calls
whenever the guardrail isn't actually running — including in the automated test suite's default run and every
`tests/test_guardrail_bypass.py` case that doesn't explicitly enable both flags via `monkeypatch`.
