"""AgentGuard MCP server: a drop-in MCP server that any MCP-compatible AI
coding assistant (Claude Code, Cursor, etc.) can point at instead of a raw
filesystem server — every tool call passes through PolicyMiddleware first.

Run directly for local testing:
    python -m app.server

Wire into Claude Code via .mcp.json (see ../README.md).
"""
from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from .audit import AuditLogger
from .config import load_policy
from .middleware import PolicyMiddleware

PROXY_ROOT = Path(__file__).resolve().parent.parent

# Overridable so tests (and anyone running multiple AgentGuard instances)
# can point at an isolated policy/sandbox instead of the real one on disk.
POLICY_PATH = Path(os.environ.get("AGENTGUARD_POLICY_PATH", PROXY_ROOT / "policy.yaml"))
AUDIT_PATH = Path(os.environ.get("AGENTGUARD_AUDIT_PATH", PROXY_ROOT / "audit.log"))

cfg = load_policy(POLICY_PATH)
# Per-task write scope from whoever launches the proxy (e.g. the harness):
# AGENTGUARD_WRITABLE_PATHS="summary.md,notes/*" overrides policy.yaml.
if os.environ.get("AGENTGUARD_WRITABLE_PATHS"):
    cfg.writable_paths = [p.strip() for p in os.environ["AGENTGUARD_WRITABLE_PATHS"].split(",") if p.strip()]
audit = AuditLogger(AUDIT_PATH)

mcp_app = MCPServer(
    name="agentguard",
    instructions=(
        "A policy-enforcing proxy for AI-agent filesystem access. "
        "Every tool call is checked against policy.yaml before it runs."
    ),
    middleware=[PolicyMiddleware(cfg, audit)],
)


def _sandbox_path(raw_path: str) -> Path:
    """Defense-in-depth: re-check sandbox containment inside the tool itself,
    not only in the middleware. If the middleware were ever misconfigured or
    bypassed, this is the second independent layer that still refuses to
    escape the sandbox — see docs/THREAT_MODEL.md.
    """
    candidate = (cfg.sandbox_root / raw_path).resolve()
    candidate.relative_to(cfg.sandbox_root)  # raises ValueError if outside
    return candidate


@mcp_app.tool()
def read_file(path: str) -> str:
    """Read a text file's contents from within the AgentGuard sandbox."""
    return _sandbox_path(path).read_text()


@mcp_app.tool()
def write_file(path: str, content: str) -> str:
    """Write text content to a file within the AgentGuard sandbox."""
    target = _sandbox_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return f"wrote {len(content)} bytes to {path}"


@mcp_app.tool()
def delete_file(path: str) -> str:
    """Delete a file within the AgentGuard sandbox.

    Currently always denied by PolicyMiddleware (risk: destructive, no
    approval flow yet) — this function body only runs once Phase 2 adds a
    human-approval path that can actually let a call through.
    """
    target = _sandbox_path(path)
    target.unlink()
    return f"deleted {path}"


def main() -> None:
    mcp_app.run(transport="stdio")


if __name__ == "__main__":
    main()
