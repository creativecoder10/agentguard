"""Structured audit logging — one JSON line per tool-call decision.

Same shape as the Splunk-style events in the interview notes: one
timestamped event per action, not a pre-aggregated summary, so a denied
call (the interesting signal — something tried to go out of scope) is
never lost in a rollup.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, *, tool: str, arguments: dict[str, Any], decision: str, reason: str) -> None:
        entry = {
            "ts": time.time(),
            "tool": tool,
            "arguments": arguments,
            "decision": decision,  # "ALLOW" | "DENY"
            "reason": reason,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
