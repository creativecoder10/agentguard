"""Unit tests for the policy engine — the part of AgentGuard that decides
ALLOW/DENY independent of the MCP protocol plumbing around it.

Each test is a concrete attack or edge case from docs/THREAT_MODEL.md, not
an abstract "it works" check: path traversal, an absolute path outside the
sandbox, an unlisted tool, a blocked extension, and a destructive tool.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.config import PolicyConfig, ToolPolicy
from app.policy import evaluate


@pytest.fixture
def cfg(tmp_path: Path) -> PolicyConfig:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    return PolicyConfig(
        sandbox_root=sandbox,
        tools={
            "read_file": ToolPolicy(risk="read"),
            "write_file": ToolPolicy(risk="write"),
            "delete_file": ToolPolicy(risk="destructive"),
        },
        blocked_extensions=[".env", ".pem"],
    )


def test_allows_read_within_sandbox(cfg: PolicyConfig) -> None:
    (cfg.sandbox_root / "notes.txt").write_text("hello")
    decision = evaluate("read_file", {"path": "notes.txt"}, cfg)
    assert decision.allowed


def test_denies_path_traversal_out_of_sandbox(cfg: PolicyConfig) -> None:
    decision = evaluate("read_file", {"path": "../../../../etc/passwd"}, cfg)
    assert not decision.allowed
    assert "outside the sandbox" in decision.reason


def test_denies_absolute_path_outside_sandbox(cfg: PolicyConfig) -> None:
    decision = evaluate("read_file", {"path": "/etc/passwd"}, cfg)
    assert not decision.allowed
    assert "outside the sandbox" in decision.reason


def test_denies_tool_not_on_allowlist(cfg: PolicyConfig) -> None:
    decision = evaluate("run_shell_command", {"path": "notes.txt"}, cfg)
    assert not decision.allowed
    assert "not on the allowlist" in decision.reason


def test_denies_blocked_extension(cfg: PolicyConfig) -> None:
    decision = evaluate("write_file", {"path": "secrets.env", "content": "x"}, cfg)
    assert not decision.allowed
    assert "blocked" in decision.reason


def test_denies_destructive_tool_pending_phase_2_approval(cfg: PolicyConfig) -> None:
    decision = evaluate("delete_file", {"path": "notes.txt"}, cfg)
    assert not decision.allowed
    assert "requires human approval" in decision.reason


def test_denies_missing_path_argument(cfg: PolicyConfig) -> None:
    decision = evaluate("read_file", {}, cfg)
    assert not decision.allowed
    assert "missing required" in decision.reason


def test_allows_write_within_nested_sandbox_dir(cfg: PolicyConfig) -> None:
    decision = evaluate("write_file", {"path": "notes/todo.txt", "content": "x"}, cfg)
    assert decision.allowed
