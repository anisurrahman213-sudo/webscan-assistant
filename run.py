"""
run.py -- CLI: run recon tools against one target, with optional advice,
correlation, and an HTML report.

    python3 run.py --target http://testphp.vulnweb.com
    python3 run.py --target http://testphp.vulnweb.com --yes --report
    python3 run.py --target http://testphp.vulnweb.com --advise

Approval rules: every action asks for y/N. With --yes, recon at 'active-safe'
or lower is auto-approved; anything intrusive or above STILL asks.
--advise uses the LLM brain to triage and suggest a next tool -- it only
PRINTS the suggestion; it never runs anything on its own.
"""
from __future__ import annotations

import argparse

from scope import Scope, RiskLevel
from audit import AuditLog
from approval import ApprovalGate, ProposedAction, cli_prompt
from registry import ToolRegistry
from runner import ToolRunner
from tools.http_headers import HttpHeadersTool
from tools.tech_detect import TechDetectTool
from tools.port_scan import build as build_port_scan
from correlation import correlate
from report import write_report


def _make_prompt(auto: bool):
    def prompt(action: ProposedAction, scope_reason: str) -> bool:
        if auto and action.risk.rank <= RiskLevel.ACTIVE_SAFE.rank:
            print(f"[auto-approved recon] {action.tool} -> {action.target}")
            return True
        return cli_prompt(action, scope_reason)
    return prompt


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(HttpHeadersTool())
    reg.register(TechDetectTool())
    reg.register(build_port_scan())        # wrapped external CLI (nmap)
    return reg


def main() -> None:
    ap = argparse.ArgumentParser(description="webscan-assistant runner")
    ap.add_argument("--target", required=True, help="URL to assess (must be in scope)")
    ap.add_argument("--engagement", default="engagement.yaml", help="RoE YAML path")
    ap.add_argument("--yes", action="store_true",
                    help="auto-approve recon (<= active-safe); intrusive still asks")
    ap.add_argument("--advise", action="store_true",
                    help="use the LLM brain to triage and suggest a next tool")
    ap.add_argument("--report", nargs="?", const="webscan_report.html", default=None,
                    help="write an HTML report (default: webscan_report.html)")
    args = ap.parse_args()

    scope = Scope.from_yaml(args.engagement)
    audit = AuditLog("audit.log.jsonl")
    gate = ApprovalGate(scope, audit, prompt=_make_prompt(args.yes))
    registry = build_registry()
    runner = ToolRunner(registry, gate)

    print(f"Engagement : {scope.name}")
    print(f"Target     : {args.target}")
    print("Tools      :")
    print(registry.catalog())

    all_findings = []
    for tool in registry.all():
        result = runner.run_tool(tool.name, args.target,
                                 rationale=f"Recon: {tool.description}")
        if result is None:
            print(f"\n[skipped] {tool.name} (blocked or rejected)")
        elif not result.ok:
            print(f"\n[error] {tool.name}: {result.error}")
        else:
            all_findings.extend(result.findings)

    # --- findings ---
    print("\n" + "=" * 60)
    print(f"FINDINGS ({len(all_findings)})")
    print("=" * 60)
    for f in sorted(all_findings, key=lambda x: x.severity.rank, reverse=True):
        print(" ", f.summary())

    # --- correlation ---
    paths = correlate(all_findings)
    print("\n" + "=" * 60)
    print(f"ATTACK PATHS ({len(paths)})")
    print("=" * 60)
    for p in paths:
        print(" ", p.describe())
    if not paths:
        print("  (none)")

    # --- advice (print only, never auto-run) ---
    summary_text = ""
    if args.advise:
        from llm import select_provider, LLMError
        from brain import AdvisorBrain
        provider = select_provider()
        print("\n" + "=" * 60)
        print(f"ADVISOR ({provider.name})")
        print("=" * 60)
        try:
            brain = AdvisorBrain(provider)
            summary_text = brain.triage(all_findings)
            print(summary_text)
            sug = brain.suggest_next(all_findings, registry.catalog(), args.target)
            print(f"\nSuggested next tool: {sug.tool or 'NONE'}")
            print(f"Why: {sug.rationale}")
            print("(Run it only if you approve -- nothing was executed.)")
        except LLMError as e:
            print(f"[advisor unavailable] {e}")

    # --- report ---
    if args.report:
        out = write_report(args.report, scope.name, args.target,
                           all_findings, paths, summary_text)
        print(f"\nReport written: {out}")

    print("\nAudit chain valid:", audit.verify())


if __name__ == "__main__":
    main()
