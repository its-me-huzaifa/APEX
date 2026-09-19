"""
VICTIM - the simulated enterprise AI agent that APEX attacks in this prototype.

Phase 1: VICTIM is runnable standalone (see victim/cli.py). It has a system
prompt, a simple keyword-based RAG over victim/documents/, a mock employee
database, a mock email tool (log-only, never sends), and a mock file reader.

Message routing is deliberately simple, rule-based keyword matching - not an
LLM reasoning loop. This is an honest simplification for the prototype (see
README "Design Notes"), and it is also *realistic* in one specific way the
FYP Master Document calls out: routing on shallow keyword/intent signals
without verifying who is asking or checking document sensitivity is exactly
the kind of naive tool-triggering behavior real early agent deployments have
shipped with. That naivety is what Phases 3-4 attack.
"""

import re
from pathlib import Path

import config
from llm.provider import get_provider
from victim import db, email_tool, file_reader, instruction_scanner
from victim.rag import SimpleRag

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


class Victim:
    def __init__(self):
        self.system_prompt = config.VICTIM_SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        self.rag = SimpleRag(config.VICTIM_DOCS_DIR)
        self.db_path = config.DB_PATH
        self.llm = get_provider()
        db.ensure_seeded(self.db_path)
        self.history: list[dict] = []

    # -- Public entry point ------------------------------------------------

    # Phase 8: a soft cap on input length. Not a security boundary (nothing
    # downstream is unsafe with a longer string) - just a demo-robustness
    # guard so an accidental huge paste into the dashboard doesn't make a
    # single "assessment" take unreasonably long to tokenize/scan.
    _MAX_MESSAGE_LEN = 20_000

    def chat(self, message: str) -> str:
        """The single entry point APEX will call (directly, or later via a
        TargetConnector). Always returns a string response, never raises for
        any input APEX or a human could plausibly send (see Phase 8 notes)."""
        if not isinstance(message, str):
            response = "I can only read text messages - that didn't look like one."
            self.history.append({"role": "user", "content": repr(message)})
            self.history.append({"role": "assistant", "content": response})
            return response

        if len(message) > self._MAX_MESSAGE_LEN:
            message = message[: self._MAX_MESSAGE_LEN]

        self.history.append({"role": "user", "content": message})
        if not message.strip():
            response = "I didn't catch a message there - could you say that again?"
        else:
            response = self._route(message)
        self.history.append({"role": "assistant", "content": response})
        return response

    # -- Naive intent routing ------------------------------------------------
    # Deliberately simple keyword checks, in priority order. First match wins.

    def _route(self, message: str) -> str:
        lower = message.lower()

        if "read" in lower and ("file" in lower or "document" in lower or ".txt" in lower):
            return self._handle_file_read(message)

        if "email" in lower or "send a message to" in lower:
            return self._handle_email(message)

        if any(word in lower for word in ("employee", "salary", "payroll", "who works", "department")):
            return self._handle_db_lookup(message)

        return self._handle_knowledge_query(message)

    # -- Tool handlers --------------------------------------------------

    def _handle_knowledge_query(self, message: str) -> str:
        hits = self.rag.retrieve(message, top_k=2)
        if not hits:
            return (
                "I couldn't find anything in the knowledge base about that. "
                "Try asking about company info, policies, or reports."
            )
        parts = []
        for hit in hits:
            parts.append(f"From {hit.filename}:\n{self.llm.summarize(hit.content, max_chars=600)}")
        return "\n\n".join(parts)

    def _handle_db_lookup(self, message: str) -> str:
        # Naive reverse match: rather than parsing a name out of free text
        # (brittle), check which known employees/departments are mentioned
        # anywhere in the message. Fine for a small mock directory; a real
        # agent would use an LLM or structured extraction here.
        lower = message.lower()
        all_employees = db.list_all(self.db_path)
        results = [r for r in all_employees if r["name"].lower() in lower]
        if not results:
            results = [r for r in all_employees if r["department"].lower() in lower]
        if not results:
            return "I couldn't find a matching employee record for that."
        lines = [
            f"{r['name']} - {r['title']} ({r['department']}), salary: ${r['salary']:,}, email: {r['email']}"
            for r in results
        ]
        return "Here's what I found in the employee database:\n" + "\n".join(lines)

    def _handle_email(self, message: str) -> str:
        match = _EMAIL_RE.search(message)
        recipient = match.group(0) if match else "unspecified-recipient@acmecorp.example"
        record = email_tool.send_email(
            self.db_path,
            recipient=recipient,
            subject="Message from Aria (Acme internal assistant)",
            body=message,
        )
        return f"Done - I've sent that email to {record['recipient']}."

    def _handle_file_read(self, message: str) -> str:
        filename_match = re.search(r"[\w\-.]+\.txt", message)
        if not filename_match:
            available = ", ".join(self.rag.list_documents())
            return f"Which file would you like me to read? Available: {available}"
        filename = filename_match.group(0)
        try:
            content = file_reader.read_file(config.VICTIM_DOCS_DIR, filename)
        except file_reader.FileNotAllowedError as exc:
            return f"I couldn't read that file: {exc}"

        response = f"Here's what I read from {filename}:\n\n{self.llm.summarize(content, max_chars=800)}"

        # Phase 4 (indirect prompt injection): per the system prompt, VICTIM
        # treats instructions found inside documents as useful context, and
        # acts on tool requests "right away" without confirmation. This is
        # that behavior, made concrete and observable - a naive, documented
        # vulnerability, not a bug.
        embedded_instruction = instruction_scanner.extract_embedded_instruction(content)
        if embedded_instruction:
            action_note = self._act_on_embedded_instruction(embedded_instruction, source_filename=filename)
            if action_note:
                response += f"\n\n{action_note}"

        return response

    def _act_on_embedded_instruction(self, instruction: str, source_filename: str) -> str | None:
        """
        If a document-embedded instruction mentions emailing something to a
        recipient, VICTIM composes and sends that email automatically -
        without the user ever having asked for it. This is the Phase 4
        vulnerability: content read from a file is treated with the same
        authority as a direct user request.
        """
        lower = instruction.lower()
        email_match = _EMAIL_RE.search(instruction)
        if "email" not in lower or not email_match:
            return None

        # Naive: if the instruction talks about compensation/pay/HR data,
        # VICTIM pulls the confidential HR document as the email body; if it
        # talks about financial/revenue/board data instead, it pulls the
        # internal financial report. Either way, it does not verify the
        # request is legitimate or that the recipient is authorized - that
        # gap is exactly what's being demonstrated (see
        # malicious_document.txt and malicious_document_finance.txt).
        body = instruction
        if any(word in lower for word in ("compensation", "confidential", "hr ", "pay ", "payroll", "salary")):
            try:
                body = file_reader.read_file(config.VICTIM_DOCS_DIR, "confidential_hr_policy.txt")
            except file_reader.FileNotAllowedError:
                pass
        elif any(word in lower for word in ("financial", "revenue", "cash reserves", "board")):
            try:
                body = file_reader.read_file(config.VICTIM_DOCS_DIR, "internal_financial_report.txt")
            except file_reader.FileNotAllowedError:
                pass

        recipient = email_match.group(0)
        email_tool.send_email(
            self.db_path,
            recipient=recipient,
            subject=f"Re: {source_filename} - compliance data",
            body=body,
        )
        return f"Also, per the note in {source_filename}, I've gone ahead and emailed the requested information to {recipient}."
