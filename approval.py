"""
approval.py -- The Human Approval Gate.

The assistant may only *propose* actions. Nothing active reaches a target until
a human approves it here.

Guarantees:
  * Scope is checked FIRST. An out-of-scope proposal is BLOCKED outright and is
    never even offered to the human.
  * FAIL-CLOSED: if no human answers (non-interactive stdin / EOF), the decision
    is REJECT -- never approve.
  * Every proposal and decision is written to the tamper-evident audit log.

The prompt function is injectable, so the same gate can later be driven by a
Telegram bot or a GUI instead of the terminal -- without changing the rules.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from scope import Scope, RiskLevel, ScopeDecision
from audit import AuditLog


class Decision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    BLOCKED = "blocked"      # denied by scope; the human was never asked


@dataclass
class ProposedAction:
    tool: str                       # module/tool the brain wants to run
    target: str
    risk: RiskLevel
    rationale: str                  # WHY the assistant suggests this
    params: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8]}")

    def describe(self) -> str:
        return "\n".join([
            f"  Action : {self.id}",
            f"  Tool   : {self.tool}",
            f"  Target : {self.target}",
            f"  Risk   : {self.risk.value}",
            f"  Params : {self.params or '{}'}",
            f"  Why    : {self.rationale}",
        ])


@dataclass
class ApprovalResult:
    action: ProposedAction
    decision: Decision
    reason: str

    @property
    def approved(self) -> bool:
        return self.decision is Decision.APPROVED


# A prompt takes the action + the scope reason and returns True to approve.
PromptFn = Callable[[ProposedAction, str], bool]


def cli_prompt(action: ProposedAction, scope_reason: str) -> bool:
    print("\n" + "=" * 60)
    print("APPROVAL REQUIRED")
    print("=" * 60)
    print(action.describe())
    print(f"  Scope  : {scope_reason}")
    print("-" * 60)
    try:
        answer = input("Approve this action? [y/N]: ").strip().lower()
    except EOFError:
        return False                 # fail-closed: no human -> no
    return answer in ("y", "yes")


class ApprovalGate:
    def __init__(self, scope: Scope,
                 audit: Optional[AuditLog] = None,
                 prompt: PromptFn = cli_prompt) -> None:
        self.scope = scope
        self.audit = audit or AuditLog()
        self._prompt = prompt

    def request(self, action: ProposedAction) -> ApprovalResult:
        # 1) scope first -- fail closed
        verdict: ScopeDecision = self.scope.check(action.target, action.risk)
        self.audit.record("action_proposed", {
            "action": action.id, "tool": action.tool, "target": action.target,
            "risk": action.risk.value, "rationale": action.rationale,
            "in_scope": verdict.allowed, "scope_reason": verdict.reason,
        })
        if not verdict.allowed:
            self.audit.record("action_blocked",
                              {"action": action.id, "reason": verdict.reason})
            return ApprovalResult(action, Decision.BLOCKED, verdict.reason)

        # 2) the human decides
        approved = self._prompt(action, verdict.reason)
        decision = Decision.APPROVED if approved else Decision.REJECTED
        self.audit.record("human_decision",
                          {"action": action.id, "decision": decision.value})
        return ApprovalResult(
            action, decision,
            "approved by operator" if approved else "rejected by operator",
        )
