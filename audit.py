"""
audit.py -- Append-only, tamper-evident audit log.

Every proposal and every human decision is written here as one JSON line.
Each entry stores the hash of the previous entry, forming a hash chain: if any
earlier line is altered or deleted, verify() breaks. This is what lets you
prove, after an engagement, exactly what was proposed and what you approved.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
_HASHED_KEYS = ("ts", "event", "data", "prev_hash")


class AuditLog:
    def __init__(self, path: str | Path = "audit.log.jsonl") -> None:
        self.path = Path(path)
        self.path.touch(exist_ok=True)

    def _last_hash(self) -> str:
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line)["entry_hash"]
                except (json.JSONDecodeError, KeyError):
                    continue
        return last

    def record(self, event: str, data: dict[str, Any]) -> str:
        body = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data,
            "prev_hash": self._last_hash(),
        }
        payload = json.dumps(body, sort_keys=True, ensure_ascii=False)
        body["entry_hash"] = hashlib.sha256(
            (body["prev_hash"] + payload).encode("utf-8")
        ).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, ensure_ascii=False) + "\n")
        return body["entry_hash"]

    def verify(self) -> bool:
        prev = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                stored = entry.get("entry_hash")
                if entry.get("prev_hash") != prev:
                    return False
                payload = json.dumps(
                    {k: entry[k] for k in _HASHED_KEYS},
                    sort_keys=True, ensure_ascii=False,
                )
                recomputed = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
                if recomputed != stored:
                    return False
                prev = stored
        return True
