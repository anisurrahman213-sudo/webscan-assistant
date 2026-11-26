"""
demo_phase1.py -- Offline smoke test of the Phase 1 framework (no network).

Verifies two things without touching any target:
  1. The registry -> runner -> approval-gate wiring, using a mock tool.
  2. The HTTP-headers analysis logic, fed fake headers.

    python3 demo_phase1.py
"""
from typing import Any, Optional

from finding import Finding, Severity
from scope import Scope, RiskLevel
from audit import AuditLog
from approval import ApprovalGate, ProposedAction
from registry import ToolRegistry
from runner import ToolRunner
from tool import Tool, ToolResult
from tools.http_headers import HttpHeadersTool


class MockTool(Tool):
    name = "mock_recon"
    description = "offline mock that returns a canned finding"
    category = "mock"
    risk = RiskLevel.PASSIVE

    def run(self, target: str, params: Optional[dict[str, Any]] = None) -> ToolResult:
        f = Finding(title="Mock finding", severity=Severity.INFO,
                    target=target, category="mock", module=self.name)
        return ToolResult(self.name, target, ok=True, findings=[f], raw="mock")


def _auto_yes(action: ProposedAction, reason: str) -> bool:
    print(f"[auto-approved] {action.tool} ({action.risk.value})")
    return True


def main() -> None:
    scope = Scope.from_yaml("engagement.yaml")
    audit = AuditLog("audit.log.jsonl")
    gate = ApprovalGate(scope, audit, prompt=_auto_yes)

    reg = ToolRegistry()
    reg.register(MockTool())
    runner = ToolRunner(reg, gate)

    print("Catalog:")
    print(reg.catalog())

    print("\n1) Wiring test (mock tool through the gate):")
    res = runner.run_tool("mock_recon", "http://testphp.vulnweb.com")
    print("   findings:", [f.summary() for f in res.findings] if res else "None")

    print("\n2) Header-analysis test (fake headers, no network):")
    fake = {"server": "nginx/1.4.6 (Ubuntu)"}   # missing every security header
    hf = HttpHeadersTool()._analyze("http://testphp.vulnweb.com", 200, fake)
    print(f"   {len(hf)} findings:")
    for f in sorted(hf, key=lambda x: x.severity.rank, reverse=True):
        print("    -", f.summary())

    print("\nAudit chain valid:", audit.verify())


if __name__ == "__main__":
    main()
