"""The policy engine: the one place that decides ALLOW or DENY for a tool call.

This is the "independent policy enforcement layer" from the design notes —
deterministic code, not another LLM call, sitting between "the agent asked
for X" and "X executes." Nothing in here trusts *why* the agent wants to
call a tool, only *what* it's asking to do and whether that's in-policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from .config import PolicyConfig


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


def _resolve_within_sandbox(raw_path: str, sandbox_root: Path) -> Path | None:
    """Resolve raw_path against the sandbox root and confirm it can't escape it.

    Resolving *then* checking containment (rather than just string-matching
    for "..") is what actually blocks traversal: `.resolve()` collapses
    `../../etc/passwd` down to its real absolute path before the containment
    check ever runs, so there's no `..` left to sneak past a naive filter.
    """
    candidate = (sandbox_root / raw_path).resolve()
    try:
        candidate.relative_to(sandbox_root)
    except ValueError:
        return None
    return candidate


def sandbox_relative(raw_path: str, sandbox_root: Path) -> str | None:
    """The sandbox-relative POSIX path a raw argument resolves to, or None
    if it escapes the sandbox — what writable_paths/untrusted_sources match on."""
    resolved = _resolve_within_sandbox(raw_path, sandbox_root)
    return None if resolved is None else resolved.relative_to(sandbox_root).as_posix()


def matches_any(relative_path: str, globs: list[str]) -> bool:
    return any(fnmatch(relative_path, g) for g in globs)


def evaluate(tool_name: str, arguments: dict, cfg: PolicyConfig) -> PolicyDecision:
    tool_policy = cfg.tools.get(tool_name)
    if tool_policy is None:
        return PolicyDecision(False, f"tool '{tool_name}' is not on the allowlist")

    if tool_policy.risk == "destructive":
        # Phase 1 scope: destructive tools are hard-denied, full stop.
        # Phase 2 upgrades this to a human-approval prompt instead of a
        # blanket deny — see Plan_agentguard.md.
        return PolicyDecision(
            False,
            f"tool '{tool_name}' is destructive and requires human approval "
            "(approval flow not implemented yet — Phase 2)",
        )

    raw_path = arguments.get("path")
    if raw_path is None:
        return PolicyDecision(False, "missing required 'path' argument")

    resolved = _resolve_within_sandbox(raw_path, cfg.sandbox_root)
    if resolved is None:
        return PolicyDecision(False, f"path '{raw_path}' resolves outside the sandbox root")

    if resolved.suffix in cfg.blocked_extensions:
        return PolicyDecision(False, f"extension '{resolved.suffix}' is blocked")

    if tool_policy.risk == "write" and cfg.writable_paths is not None:
        relative = resolved.relative_to(cfg.sandbox_root).as_posix()
        if not matches_any(relative, cfg.writable_paths):
            return PolicyDecision(False, f"path '{relative}' is outside this task's writable_paths")

    return PolicyDecision(True, "ok")
