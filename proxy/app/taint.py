"""Session taint tracking: once an agent has read untrusted data, it loses
the right to change things without a human saying yes.

Why this exists: the input gate stops *out-of-policy* calls, but a hijacked
agent can still make *in-policy* ones on the attacker's behalf — e.g. write
a file inside the sandbox, or quietly edit code the user will run. Better
injection detection can't close that, because detection misses rephrased
payloads. So instead of asking "is this content malicious?", taint asks
"has this session been exposed to content we don't control?" and narrows
what it may do from then on (Meta's "Agents Rule of Two": untrusted input
+ state change = human in the loop).

A session is tainted by either:
- **source** — reading a path listed in `taint.untrusted_sources`. This is
  the robust trigger: it holds even when the scanner misses the payload.
- **signal** — any tool output that result_guard flagged as injection.
  Best-effort on its own; it inherits the scanner's blind spots.

Taint is sticky for the rest of the session: once untrusted text is in
the model's context it never leaves, so neither does the restriction.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import PolicyConfig
from .policy import PolicyDecision, matches_any, sandbox_relative


@dataclass
class SessionTaint:
    reason: str | None = None

    @property
    def tainted(self) -> bool:
        return self.reason is not None

    def mark(self, reason: str) -> bool:
        """Taint the session; returns True only on the first taint, so the
        audit log records the moment it happened, once."""
        if self.tainted:
            return False
        self.reason = reason
        return True


def taint_reason(
    tool_name: str, arguments: dict[str, Any], findings: dict[str, Any] | None, cfg: PolicyConfig
) -> str | None:
    """Why this completed call should taint the session, or None."""
    if not cfg.taint.enabled:
        return None
    raw_path = arguments.get("path")
    tool = cfg.tools.get(tool_name)
    if tool is not None and tool.risk == "read" and raw_path:
        relative = sandbox_relative(raw_path, cfg.sandbox_root)
        if relative is not None and matches_any(relative, cfg.taint.untrusted_sources):
            return f"read untrusted source '{relative}'"
    if cfg.taint.on_injection_signal and findings and findings.get("injection_signals"):
        signals = ", ".join(findings["injection_signals"])
        return f"output of {tool_name}({raw_path}) matched injection patterns ({signals})"
    return None


def check_taint(tool_name: str, taint: SessionTaint, cfg: PolicyConfig) -> PolicyDecision | None:
    """Deny a state-changing call from a tainted session; None = no objection."""
    tool = cfg.tools.get(tool_name)
    if not cfg.taint.enabled or not taint.tainted or tool is None or tool.risk not in cfg.taint.blocks_risk:
        return None
    return PolicyDecision(
        False,
        f"session is tainted ({taint.reason}) — '{tool_name}' changes state and needs "
        "human approval after untrusted input (approval flow not implemented yet — Phase 2)",
    )
