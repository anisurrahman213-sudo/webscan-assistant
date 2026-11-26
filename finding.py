"""
finding.py -- Normalized security finding model.

Every tool/module in the assistant emits Findings in this one shape, so the
reasoning brain, the correlation view and the reporting engine all speak a
single language. This module is pure data + (de)serialization: no I/O, no
network, no side effects.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


class Confidence(str, Enum):
    TENTATIVE = "tentative"   # might be a false positive
    FIRM = "firm"             # strong signal, not yet proven
    CONFIRMED = "confirmed"   # verified / reproduced by a human


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return f"FND-{uuid.uuid4().hex[:12]}"


@dataclass
class Finding:
    # --- required ---
    title: str
    severity: Severity
    target: str                       # host or URL the finding relates to
    category: str                     # short tag: "sqli", "xss", "info-leak"...
    # --- optional ---
    description: str = ""
    confidence: Confidence = Confidence.TENTATIVE
    affected_param: Optional[str] = None
    evidence: str = ""                # trimmed request/response snippet
    module: str = ""                  # which tool/module produced it
    cvss: Optional[float] = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)      # used by correlation
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        # Accept plain strings for the enums (e.g. coming from JSON / an LLM).
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.lower())
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence.lower())
        if self.cvss is not None and not (0.0 <= self.cvss <= 10.0):
            raise ValueError(f"cvss must be 0.0-10.0, got {self.cvss}")

    # ---- serialization ------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})

    # ---- convenience --------------------------------------------------
    def summary(self) -> str:
        param = f" (param: {self.affected_param})" if self.affected_param else ""
        return f"[{self.severity.value.upper()}] {self.title} @ {self.target}{param}"
