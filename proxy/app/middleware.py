"""MCP protocol-level middleware that enforces policy on every tool call.

This is the key architectural choice: the gate lives at the MCP protocol
layer (intercepting the raw `tools/call` JSON-RPC request before it reaches
any tool's Python function), not hand-checked inside each tool. That means
every tool registered on this server — today's three, or a hundred added
later — passes through the same gate automatically. A new tool can't
accidentally ship without policy coverage, the way it could if each tool
function had to remember to call a check itself.
"""
from __future__ import annotations

from typing import Any

from mcp_types import CallToolResult, TextContent

from mcp.server.context import CallNext, HandlerResult, ServerMiddleware, ServerRequestContext

from .audit import AuditLogger
from .config import PolicyConfig
from .policy import evaluate


class PolicyMiddleware(ServerMiddleware[Any]):
    """Context-tier middleware: denies out-of-policy `tools/call` requests
    before they ever reach the tool's handler function.
    """

    def __init__(self, cfg: PolicyConfig, audit: AuditLogger) -> None:
        self.cfg = cfg
        self.audit = audit

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)

        name = ctx.params.get("name")
        arguments = ctx.params.get("arguments") or {}

        decision = evaluate(name, arguments, self.cfg)

        if not decision.allowed:
            self.audit.log(tool=name, arguments=arguments, decision="DENY", reason=decision.reason)
            return CallToolResult(
                content=[TextContent(type="text", text=f"DENIED by AgentGuard policy: {decision.reason}")],
                isError=True,
            )

        result = await call_next(ctx)
        self.audit.log(tool=name, arguments=arguments, decision="ALLOW", reason=decision.reason)
        return result
