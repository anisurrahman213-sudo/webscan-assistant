"""
correlation.py -- Rule-based attack-path view (deterministic, no LLM).

Takes the flat list of findings and surfaces how separate issues could combine
into a bigger risk. This is an ANALYSIS aid for the human: it describes possible
paths so you can judge impact and prioritize fixes. It executes nothing and
produces no exploit steps -- only "these findings, together, could mean X".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from finding import Finding, Severity


@dataclass(frozen=True)
class ChainRule:
    name: str
    requires: tuple[str, ...]      # categories/tags that must ALL be present
    impact: str
    severity: Severity


RULES: tuple[ChainRule, ...] = (
    ChainRule("Account takeover", ("idor", "auth-bypass"),
              "IDOR plus an auth bypass can let one user control another's account.",
              Severity.CRITICAL),
    ChainRule("RCE via file upload", ("file-upload", "lfi"),
              "An unrestricted upload reachable via LFI/path can lead to code execution.",
              Severity.CRITICAL),
    ChainRule("OAuth token theft", ("open-redirect", "oauth"),
              "An open redirect in an OAuth flow can leak tokens to an attacker URL.",
              Severity.HIGH),
    ChainRule("Session hijack via XSS", ("xss", "cookie-insecure"),
              "XSS plus cookies lacking HttpOnly enables session theft.",
              Severity.HIGH),
    ChainRule("Cloud/internal pivot via SSRF", ("ssrf", "metadata"),
              "SSRF able to reach a metadata/internal service may expose credentials.",
              Severity.HIGH),
)


@dataclass
class AttackPath:
    name: str
    impact: str
    severity: Severity
    links: list[Finding] = field(default_factory=list)

    def describe(self) -> str:
        chain = " -> ".join(f.category for f in self.links)
        return f"[{self.severity.value.upper()}] {self.name}: {chain}"


def _labels(f: Finding) -> set[str]:
    return {f.category.lower(), *(t.lower() for t in f.tags)}


def correlate(findings: list[Finding]) -> list[AttackPath]:
    paths: list[AttackPath] = []
    for rule in RULES:
        matched: list[Finding] = []
        for req in rule.requires:
            hit = next((f for f in findings if req in _labels(f)), None)
            if hit is None:
                matched = []
                break
            matched.append(hit)
        if matched:
            paths.append(AttackPath(rule.name, rule.impact, rule.severity, matched))
    paths.sort(key=lambda p: p.severity.rank, reverse=True)
    return paths
