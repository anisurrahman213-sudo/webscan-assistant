"""
tool.py -- The uniform interface every module/tool implements.

A Tool knows its own name, what it does, and its risk level. It runs against a
target and returns a ToolResult: normalized Findings plus the raw output. The
runner (runner.py) is what actually gates and executes a Tool -- a Tool never
decides on its own whether it is allowed to run.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from finding import Finding
from scope import RiskLevel


@dataclass
class ToolResult:
    tool: str
    target: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    raw: str = ""
    error: str = ""


class Tool(ABC):
    """Subclass and set the four class attributes + implement run()."""
    name: str = "unnamed-tool"
    description: str = ""
    category: str = "generic"
    risk: RiskLevel = RiskLevel.ACTIVE_SAFE

    @abstractmethod
    def run(self, target: str, params: Optional[dict[str, Any]] = None) -> ToolResult:
        """Execute against target. Must never raise -- capture errors in the
        returned ToolResult (ok=False, error=...)."""
        raise NotImplementedError

    # a one-line catalog entry the registry / brain can read
    def signature(self) -> str:
        return f"{self.name} [{self.risk.value}] -- {self.description}"
