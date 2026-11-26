"""
registry.py -- The catalog of available tools.

The assistant asks the registry "what weapons do I have?" and looks a tool up by
name. That's all it does; it holds no logic about whether a tool may run.
"""
from __future__ import annotations

from tool import Tool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool name: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"no such tool: {name}")
        return self._tools[name]

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def catalog(self) -> str:
        if not self._tools:
            return "(no tools registered)"
        return "\n".join(f"  - {t.signature()}" for t in self._tools.values())
