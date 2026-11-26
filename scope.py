"""
scope.py -- Rules of Engagement (RoE) loader and scope enforcement.

Loads an engagement definition from YAML and answers one question safely:

    "Is this target, at this time, for this risk level, allowed?"

Design rule: FAIL-CLOSED. Anything not explicitly placed in scope is DENIED,
and an explicit out-of-scope entry always wins.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "PyYAML is required. Install it with:\n"
        "    pip install --break-system-packages pyyaml"
    ) from exc


class RiskLevel(str, Enum):
    PASSIVE = "passive"          # read-only recon, nothing that changes state
    ACTIVE_SAFE = "active-safe"  # active probing, non-intrusive
    INTRUSIVE = "intrusive"      # exploitation attempts, injection, auth bypass
    DESTRUCTIVE = "destructive"  # may damage data or availability

    @property
    def rank(self) -> int:
        order = [RiskLevel.PASSIVE, RiskLevel.ACTIVE_SAFE,
                 RiskLevel.INTRUSIVE, RiskLevel.DESTRUCTIVE]
        return order.index(self)


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class Scope:
    name: str
    in_scope_domains: list[str] = field(default_factory=list)
    in_scope_ips: list[str] = field(default_factory=list)       # CIDR or single
    out_of_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_ips: list[str] = field(default_factory=list)
    max_risk: RiskLevel = RiskLevel.ACTIVE_SAFE
    forbidden_risks: list[RiskLevel] = field(default_factory=list)
    time_start: Optional[time] = None
    time_end: Optional[time] = None

    # ---- loading ------------------------------------------------------
    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scope":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        eng = raw.get("engagement", {}) or {}
        in_s = raw.get("in_scope", {}) or {}
        out_s = raw.get("out_of_scope", {}) or {}
        rules = raw.get("rules", {}) or {}

        tw = rules.get("time_window") or {}
        return cls(
            name=eng.get("name", "unnamed-engagement"),
            in_scope_domains=[d.lower() for d in (in_s.get("domains") or [])],
            in_scope_ips=list(in_s.get("ips") or []),
            out_of_scope_domains=[d.lower() for d in (out_s.get("domains") or [])],
            out_of_scope_ips=list(out_s.get("ips") or []),
            max_risk=RiskLevel(rules.get("max_risk", "active-safe")),
            forbidden_risks=[RiskLevel(r) for r in (rules.get("forbidden_actions") or [])],
            time_start=_parse_time(tw.get("start")),
            time_end=_parse_time(tw.get("end")),
        )

    # ---- the one public check -----------------------------------------
    def check(self, target: str, risk: RiskLevel,
              *, now: Optional[datetime] = None) -> ScopeDecision:
        host = _extract_host(target)
        if not host:
            return ScopeDecision(False, f"could not parse a host from target: {target!r}")

        # 1) explicit out-of-scope always wins
        if self._matches(host, self.out_of_scope_domains, self.out_of_scope_ips):
            return ScopeDecision(False, f"{host} is explicitly OUT of scope")

        # 2) must be inside the authorized scope
        if not self._matches(host, self.in_scope_domains, self.in_scope_ips):
            return ScopeDecision(False, f"{host} is not in the authorized scope")

        # 3) risk ceiling
        if risk in self.forbidden_risks:
            return ScopeDecision(False, f"action risk '{risk.value}' is forbidden by RoE")
        if risk.rank > self.max_risk.rank:
            return ScopeDecision(
                False,
                f"risk '{risk.value}' exceeds max allowed '{self.max_risk.value}'",
            )

        # 4) time window
        if self.time_start and self.time_end:
            now = now or datetime.now()
            if not _within_window(now.time(), self.time_start, self.time_end):
                return ScopeDecision(
                    False,
                    f"outside permitted window ({self.time_start}-{self.time_end})",
                )

        return ScopeDecision(True, f"{host} in scope; risk '{risk.value}' permitted")

    # ---- matching -----------------------------------------------------
    def _matches(self, host: str, domains: list[str], ips: list[str]) -> bool:
        ip_obj = _as_ip(host)
        if ip_obj is not None:
            for net in ips:
                try:
                    if ip_obj in ipaddress.ip_network(net, strict=False):
                        return True
                except ValueError:
                    continue
            return False
        for pattern in domains:
            if host == pattern or fnmatch.fnmatch(host, pattern):
                return True
        return False


# --- small helpers -----------------------------------------------------
def _parse_time(value: Optional[str]) -> Optional[time]:
    if not value:
        return None
    hh, mm = str(value).split(":")
    return time(int(hh), int(mm))


def _within_window(now: time, start: time, end: time) -> bool:
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end       # window crosses midnight


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _extract_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()
