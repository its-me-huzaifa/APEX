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

## 11. No LLM is required, and none is used by default

`llm/provider.py` defines a pluggable `LLMProvider` interface. The default `RuleBasedProvider` is what the
whole prototype runs on — zero cost, zero extra RAM, no model download. An optional `LocalOllamaProvider` for
a small (1–2B parameter) local model exists in the code but is off by default and was never required to be
enabled for any phase of this build.
