"""
llm.py -- Minimal multi-provider LLM client for the advisor brain.

Provider priority (matches the project): anthropic -> openai -> google -> ollama.
A MockProvider is always available so the system works offline for development.

Calls go over raw HTTPS (no SDK dependency). Model names come from env vars so
you can point at whatever you have access to; defaults are used otherwise.

    ANTHROPIC_API_KEY / ANTHROPIC_MODEL
    OPENAI_API_KEY    / OPENAI_MODEL
    GOOGLE_API_KEY    / GOOGLE_MODEL      (Gemini)
    OLLAMA_HOST       / OLLAMA_MODEL
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional, Protocol


class LLMError(RuntimeError):
    pass


class LLMProvider(Protocol):
    name: str
    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str: ...


def _post_json(url: str, headers: dict, payload: dict, timeout: int = 60) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise LLMError(f"{e.code} {e.reason}: {body[:300]}") from e
    except Exception as e:  # noqa: BLE001
        raise LLMError(str(e)) from e


class MockProvider:
    """Deterministic, offline. Echoes the first line of the prompt."""
    name = "mock"

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        first = user.strip().splitlines()[0] if user.strip() else "(empty)"
        return f"[mock-llm] {first[:160]}"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self) -> None:
        self.key = os.environ["ANTHROPIC_API_KEY"]
        self.model = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        out = _post_json(
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": self.key, "anthropic-version": "2023-06-01",
             "content-type": "application/json"},
            {"model": self.model, "max_tokens": max_tokens, "system": system,
             "messages": [{"role": "user", "content": user}]},
        )
        return "".join(b.get("text", "") for b in out.get("content", []))


class OpenAIProvider:
    name = "openai"

    def __init__(self) -> None:
        self.key = os.environ["OPENAI_API_KEY"]
        self.model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        out = _post_json(
            "https://api.openai.com/v1/chat/completions",
            {"Authorization": f"Bearer {self.key}", "content-type": "application/json"},
            {"model": self.model, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
        )
        return out["choices"][0]["message"]["content"]


class GoogleProvider:
    name = "google"

    def __init__(self) -> None:
        self.key = os.environ["GOOGLE_API_KEY"]
        self.model = os.environ.get("GOOGLE_MODEL", "gemini-1.5-flash")

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.model}:generateContent?key={self.key}")
        out = _post_json(
            url, {"content-type": "application/json"},
            {"system_instruction": {"parts": [{"text": system}]},
             "contents": [{"role": "user", "parts": [{"text": user}]}],
             "generationConfig": {"maxOutputTokens": max_tokens}},
        )
        try:
            parts = out["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected Gemini response: {str(out)[:200]}") from e
        return "".join(p.get("text", "") for p in parts)


class OllamaProvider:
    name = "ollama"

    def __init__(self) -> None:
        self.host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        self.model = os.environ.get("OLLAMA_MODEL", "llama3")

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        out = _post_json(
            f"{self.host}/api/chat",
            {"content-type": "application/json"},
            {"model": self.model, "stream": False,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
        )
        return out.get("message", {}).get("content", "")


def select_provider(*, allow_mock_fallback: bool = True) -> Optional[LLMProvider]:
    """Pick the first configured provider by priority. Falls back to Mock."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicProvider()
    if os.environ.get("OPENAI_API_KEY"):
        return OpenAIProvider()
    if os.environ.get("GOOGLE_API_KEY"):
        return GoogleProvider()
    if os.environ.get("OLLAMA_HOST") or os.environ.get("OLLAMA_MODEL"):
        return OllamaProvider()
    return MockProvider() if allow_mock_fallback else None
