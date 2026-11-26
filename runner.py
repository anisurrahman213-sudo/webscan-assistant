"""
runner.py -- Ties a Tool to the Phase 0 Approval Gate.

Flow for every tool run:
    tool -> ProposedAction -> ApprovalGate (scope check + human) -> execute

Nothing executes unless the gate approves. Execution is wrapped so a crashing
tool becomes a failed ToolResult, never an exception that escapes.
"""
from __future__ import annotations

from typing import Any, Optional

from approval import ApprovalGate, ProposedAction
from registry import ToolRegistry
from tool import ToolResult


class ToolRunner:
    def __init__(self, registry: ToolRegistry, gate: ApprovalGate) -> None:
        self.registry = registry
        self.gate = gate

    def run_tool(self, name: str, target: str,
                 params: Optional[dict[str, Any]] = None,
                 rationale: str = "") -> Optional[ToolResult]:
        """Returns a ToolResult if the action was approved and ran, else None
        (blocked by scope or rejected by the operator)."""
        tool = self.registry.get(name)
        action = ProposedAction(
            tool=name, target=target, risk=tool.risk,
            rationale=rationale or tool.description, params=params or {},
        )

        decision = self.gate.request(action)
        if not decision.approved:
            return None   # blocked or rejected -- gate already logged why

        # approved -> execute, fail-safe
        try:
            result = tool.run(target, params or {})
        except Exception as exc:  # a tool should not raise, but never trust it
            result = ToolResult(name, target, ok=False, error=f"tool crashed: {exc}")

        self.gate.audit.record("tool_executed", {
            "action": action.id, "tool": name, "target": target,
            "ok": result.ok, "findings": len(result.findings),
            "error": result.error,
        })
        return result
