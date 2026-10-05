"""Unit tests for session taint (app/taint.py): what taints a session, and
what a tainted session may still do."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.config import PolicyConfig, TaintPolicy, ToolPolicy
from app.taint import SessionTaint, check_taint, taint_reason


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
        taint=TaintPolicy(untrusted_sources=["inbox/*"]),
    )


def test_reading_untrusted_source_taints(cfg: PolicyConfig) -> None:
    assert taint_reason("read_file", {"path": "inbox/mail.md"}, None, cfg) == "read untrusted source 'inbox/mail.md'"


def test_reading_trusted_file_does_not_taint(cfg: PolicyConfig) -> None:
    assert taint_reason("read_file", {"path": "src/app.py"}, None, cfg) is None


def test_untrusted_glob_matches_after_path_resolution(cfg: PolicyConfig) -> None:
    # "src/../inbox/x" is still the inbox — matching runs on the resolved path.
    assert taint_reason("read_file", {"path": "src/../inbox/x.md"}, None, cfg) is not None


def test_injection_signal_taints_any_source(cfg: PolicyConfig) -> None:
    findings = {"injection_signals": ["override_instructions"]}
    assert "matched injection patterns" in taint_reason("read_file", {"path": "src/app.py"}, findings, cfg)


def test_taint_disabled_never_taints(cfg: PolicyConfig) -> None:
    cfg.taint.enabled = False
    assert taint_reason("read_file", {"path": "inbox/mail.md"}, None, cfg) is None


def test_tainted_session_blocks_write_and_destructive_but_not_read(cfg: PolicyConfig) -> None:
    taint = SessionTaint()
    taint.mark("read untrusted source 'inbox/mail.md'")
    assert check_taint("write_file", taint, cfg).allowed is False
    assert check_taint("delete_file", taint, cfg).allowed is False
    assert check_taint("read_file", taint, cfg) is None


def test_clean_session_has_no_objection(cfg: PolicyConfig) -> None:
    assert check_taint("write_file", SessionTaint(), cfg) is None


def test_taint_is_sticky_and_keeps_first_reason() -> None:
    taint = SessionTaint()
    assert taint.mark("first") is True
    assert taint.mark("second") is False
    assert taint.reason == "first"
