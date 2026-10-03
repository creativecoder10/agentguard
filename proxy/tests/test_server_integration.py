"""End-to-end proof: a real MCP client, talking the real MCP protocol over
stdio to a real AgentGuard server subprocess, gets denied for an out-of-
policy call and allowed for an in-policy one.

This is the test that actually matters for the product's core claim: the
gate holds at the protocol boundary a real AI client would use, not just in
a unit test that calls evaluate() directly in-process.
"""
from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROXY_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def server_params(tmp_path: Path) -> StdioServerParameters:
    # Write an isolated policy.yaml pointing at a per-test sandbox, and pass
    # it via AGENTGUARD_POLICY_PATH so these tests never touch the real
    # proxy/sandbox/ or proxy/audit.log on disk.
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """\
            sandbox_root: "./sandbox"
            tools:
              read_file:
                risk: read
              write_file:
                risk: write
              delete_file:
                risk: destructive
            blocked_extensions:
              - .env
              - .pem
            """
        )
    )
    audit_path = tmp_path / "audit.log"

    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "app.server"],
        cwd=str(PROXY_ROOT),
        env={
            **os.environ,
            "AGENTGUARD_POLICY_PATH": str(policy_path),
            "AGENTGUARD_AUDIT_PATH": str(audit_path),
        },
    )


@pytest.mark.asyncio
async def test_write_then_read_within_sandbox_succeeds(server_params: StdioServerParameters) -> None:
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            write_result = await session.call_tool(
                "write_file", {"path": "integration_test.txt", "content": "hello from a real MCP client"}
            )
            assert write_result.is_error is not True

            read_result = await session.call_tool("read_file", {"path": "integration_test.txt"})
            assert read_result.is_error is not True
            text = read_result.content[0].text
            assert "hello from a real MCP client" in text


@pytest.mark.asyncio
async def test_path_traversal_is_denied_over_real_protocol(server_params: StdioServerParameters) -> None:
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.call_tool("read_file", {"path": "../../../../etc/passwd"})
            assert result.is_error is True
            assert "DENIED" in result.content[0].text
            assert "outside the sandbox" in result.content[0].text


@pytest.mark.asyncio
async def test_destructive_tool_is_denied_over_real_protocol(server_params: StdioServerParameters) -> None:
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.call_tool("delete_file", {"path": "integration_test.txt"})
            assert result.is_error is True
            assert "DENIED" in result.content[0].text
            assert "requires human approval" in result.content[0].text
