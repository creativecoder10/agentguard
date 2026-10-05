"""Loads policy.yaml into a typed config object.

Java analogy: this is the Jackson-style "deserialize YAML into a typed
config class" step — Pydantic plays the role of the binding layer, same job
as a Spring Boot @ConfigurationProperties class, just without the XML/
annotation ceremony.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel


class ToolPolicy(BaseModel):
    risk: str  # "read" | "write" | "destructive"


class ResultScanningPolicy(BaseModel):
    """What happens to a tool's *output* before the agent sees it — see
    app/result_guard.py."""

    enabled: bool = True
    redact_secrets: bool = True
    on_injection: Literal["flag", "block"] = "flag"


class TaintPolicy(BaseModel):
    """Session taint tracking — see app/taint.py. Once a session has read
    untrusted data, tools in `blocks_risk` stop running without approval."""

    enabled: bool = True
    # fnmatch-style globs, relative to sandbox_root ("*" also crosses "/").
    # Reading a matching path taints the session whatever the scanner says.
    untrusted_sources: list[str] = []
    on_injection_signal: bool = True
    blocks_risk: list[str] = ["write", "destructive"]


class PolicyConfig(BaseModel):
    sandbox_root: Path
    tools: dict[str, ToolPolicy]
    blocked_extensions: list[str] = []
    # Task-scoped write allowlist (globs, relative to sandbox_root). None =
    # any path inside the sandbox; set per task to shrink what a hijacked
    # agent could touch even before anything is tainted.
    writable_paths: list[str] | None = None
    result_scanning: ResultScanningPolicy = ResultScanningPolicy()
    taint: TaintPolicy = TaintPolicy()


def load_policy(path: str | Path) -> PolicyConfig:
    path = Path(path)
    data = yaml.safe_load(path.read_text())
    cfg = PolicyConfig(**data)
    # Resolve relative to the policy file's own directory, not the process's
    # cwd — so `agentguard` behaves the same whether it's launched from
    # `proxy/` directly or spawned by an MCP client from anywhere else.
    cfg.sandbox_root = (path.parent / cfg.sandbox_root).resolve()
    cfg.sandbox_root.mkdir(parents=True, exist_ok=True)
    return cfg
