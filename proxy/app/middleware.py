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
from .result_guard import fence_untrusted, map_strings, redact_structured, scan_text
from .taint import SessionTaint, check_taint, taint_reason


class PolicyMiddleware(ServerMiddleware[Any]):
    """Context-tier middleware: denies out-of-policy `tools/call` requests
    before they ever reach the tool's handler function.
    """

    def __init__(self, cfg: PolicyConfig, audit: AuditLogger) -> None:
        self.cfg = cfg
        self.audit = audit
        # One middleware instance per server process, and over stdio one
        # process serves exactly one client session — so instance state *is*
        # session state. An HTTP transport serving many sessions would need
        # this keyed by session id instead.
        self.taint = SessionTaint()

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)

        name = ctx.params.get("name")
        arguments = ctx.params.get("arguments") or {}

        decision = evaluate(name, arguments, self.cfg)
        if decision.allowed:
            decision = check_taint(name, self.taint, self.cfg) or decision

        if not decision.allowed:
            self.audit.log(tool=name, arguments=arguments, decision="DENY", reason=decision.reason)
            return CallToolResult(
                content=[TextContent(type="text", text=f"DENIED by AgentGuard policy: {decision.reason}")],
                isError=True,
            )

        result = await call_next(ctx)
        result, findings = self._scan_result(result)
        reason = taint_reason(name, arguments, findings, self.cfg)
        if reason and self.taint.mark(reason):
            findings = {**(findings or {}), "session_tainted": reason}
        self.audit.log(
            tool=name, arguments=arguments, decision="ALLOW", reason=decision.reason, findings=findings
        )
        return result

    def _scan_result(self, result: HandlerResult) -> tuple[HandlerResult, dict[str, Any] | None]:
        """Output-side gate: redact secrets and flag/block prompt injection in
        what the tool returned, before it reaches the agent's context.

        By the time `call_next` returns, the SDK has already shaped the tool's
        result into the JSON-RPC wire dict (`content`, `structuredContent`,
        `isError`) — so this edits that dict, not a `CallToolResult` model.
        """
        scanning = self.cfg.result_scanning
        if not scanning.enabled or not isinstance(result, dict) or "content" not in result:
            return result, None

        secrets: list[str] = []
        signals: list[str] = []
        content = []
        for block in result["content"]:
            if block.get("type") == "text":
                scanned = scan_text(block["text"], redact=scanning.redact_secrets)
                secrets += scanned.secrets
                signals += scanned.injection_signals
                block = {**block, "text": scanned.text}
            content.append(block)

        # The SDK sends a tool's return value twice — as text `content` and as
        # `structuredContent` — so both copies get the same treatment, or the
        # secret/injection just leaks through the second one.
        structured = result.get("structuredContent")
        if structured is not None:
            structured, s, i = redact_structured(structured, redact=scanning.redact_secrets)
            secrets += s
            signals += i

        secrets = sorted(set(secrets))
        signals = sorted(set(signals))
        if not secrets and not signals:
            return result, None

        findings: dict[str, Any] = {"secrets_redacted": secrets, "injection_signals": signals}
        if signals and scanning.on_injection == "block":
            findings["action"] = "blocked"
            blocked = CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text="BLOCKED by AgentGuard: tool output matched prompt-injection patterns "
                        f"({', '.join(signals)}) and was withheld from the agent.",
                    )
                ],
                isError=True,
            )
            return blocked, findings

        if signals:
            findings["action"] = "flagged"
            content = [
                {**b, "text": fence_untrusted(b["text"], signals)} if b.get("type") == "text" else b for b in content
            ]
            structured = map_strings(structured, lambda text: fence_untrusted(text, signals))
        else:
            findings["action"] = "redacted"

        scanned_result = {**result, "content": content}
        if structured is not None:
            scanned_result["structuredContent"] = structured
        return scanned_result, findings
