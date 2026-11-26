"""
demo_phase234.py -- Offline smoke test of Phases 2, 3, 4 (no network, no API key).

  * Phase 3 correlation: synthetic findings -> attack paths
  * Phase 4 report:      write an HTML file and confirm it exists
  * Phase 2 brain:       a scripted LLM proves triage + suggestion parsing

    python3 demo_phase234.py
"""
from pathlib import Path

from finding import Finding, Severity
from correlation import correlate
from report import write_report
from brain import AdvisorBrain


def synthetic_findings() -> list[Finding]:
    mk = lambda title, sev, cat, tags=(): Finding(
        title=title, severity=sev, target="http://testphp.vulnweb.com",
        category=cat, tags=list(tags), module="demo")
    return [
        mk("IDOR on /account?id=", Severity.HIGH, "idor", ["idor"]),
        mk("Auth bypass via forced browsing", Severity.HIGH, "auth-bypass", ["auth-bypass"]),
        mk("Unrestricted file upload", Severity.HIGH, "file-upload", ["file-upload"]),
        mk("Local file inclusion in ?page=", Severity.HIGH, "lfi", ["lfi"]),
        mk("Server header reveals version", Severity.INFO, "info-leak", ["version"]),
    ]


class ScriptedLLM:
    """Stands in for a real provider so the demo needs no API key."""
    name = "scripted"

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        if user.startswith("Triage"):
            return ("Top risks: the IDOR + auth-bypass pair (account takeover) and "
                    "the upload + LFI pair (code execution). Fix those first; the "
                    "version banner is informational.")
        return "TOOL: tech_detect\nWHY: fingerprint the stack before deeper tests."


def main() -> None:
    findings = synthetic_findings()

    print("== Phase 3: correlation ==")
    paths = correlate(findings)
    for p in paths:
        print("  ", p.describe())
    assert len(paths) >= 2, "expected at least two attack paths"

    print("\n== Phase 2: advisor brain (scripted LLM) ==")
    brain = AdvisorBrain(ScriptedLLM())
    print("  triage:", brain.triage(findings))
    sug = brain.suggest_next(findings, "  - tech_detect [active-safe] -- fingerprint",
                             "http://testphp.vulnweb.com")
    print(f"  suggested tool: {sug.tool} | why: {sug.rationale}")
    assert sug.tool == "tech_detect"

    print("\n== Phase 4: report ==")
    out = write_report("demo_report.html", "Demo Engagement",
                       "http://testphp.vulnweb.com", findings, paths,
                       summary=brain.triage(findings))
    size = Path(out).stat().st_size
    print(f"  wrote {out} ({size} bytes)")
    assert size > 500

    print("\nAll Phase 2/3/4 checks passed.")


if __name__ == "__main__":
    main()
