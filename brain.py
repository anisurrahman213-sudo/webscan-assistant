"""
brain.py -- The Advisor Brain (human-in-control).

STRICT ROLE. The brain may only:
  1. explain tool output / findings in plain language,
  2. triage and prioritize findings by risk,
  3. recommend the single best NEXT TOOL to run, chosen ONLY from the catalog.

It must NOT produce exploit code, payloads, or step-by-step intrusion
instructions, and it never executes anything. Every recommendation still goes
through the human Approval Gate before it can run.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from finding import Finding
from llm import LLMProvider

SYSTEM = (
    "You are a security-assessment ADVISOR for an AUTHORIZED engagement, "
    "operating under strict human control. You may ONLY: (1) explain tool "
    "output and findings in plain language, (2) triage and prioritize findings "
    "by risk, and (3) recommend the single best next tool to run, chosen ONLY "
    "from the catalog you are given. You must NOT provide exploit code, "
    "payloads, or step-by-step intrusion instructions. A human reviews and "
    "approves every action; you never execute anything. Be concise and practical."
)


@dataclass
class Suggestion:
    tool: Optional[str]      # a tool name from the catalog, or None
    rationale: str
    raw: str


class AdvisorBrain:
    def __init__(self, llm: LLMProvider) -> None:
        self.llm = llm

    def explain(self, text: str) -> str:
        return self.llm.complete(
            SYSTEM,
            "Explain this security tool output in plain language for the "
            f"operator:\n\n{text}",
        )

    def triage(self, findings: list[Finding]) -> str:
        if not findings:
            return "No findings to triage yet."
        listing = "\n".join(
            f"- [{f.severity.value}] {f.title} @ {f.target} ({f.category})"
            for f in findings
        )
        return self.llm.complete(
            SYSTEM,
            "Triage and prioritize these findings; say what matters most and "
            f"why:\n\n{listing}",
        )

    def suggest_next(self, findings: list[Finding], catalog: str,
                     target: str) -> Suggestion:
        listing = "\n".join(
            f"- [{f.severity.value}] {f.title} ({f.category})" for f in findings
        ) or "(none yet)"
        prompt = (
            f"Target: {target}\n\nFindings so far:\n{listing}\n\n"
            "Available tools (choose ONE by exact name, or NONE if nothing "
            f"useful remains):\n{catalog}\n\n"
            "Reply in exactly this format:\nTOOL: <tool name or NONE>\n"
            "WHY: <one sentence>"
        )
        raw = self.llm.complete(SYSTEM, prompt)
        tool, why = self._parse(raw)
        return Suggestion(tool, why, raw)

    @staticmethod
    def _parse(raw: str) -> tuple[Optional[str], str]:
        tool: Optional[str] = None
        why = raw.strip()
        for line in raw.splitlines():
            s = line.strip()
            if s.upper().startswith("TOOL:"):
                v = s.split(":", 1)[1].strip()
                tool = None if v.upper() in ("NONE", "") else v
            elif s.upper().startswith("WHY:"):
                why = s.split(":", 1)[1].strip()
        return tool, why
