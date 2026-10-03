# AgentGuard

A policy-enforcing MCP proxy for AI coding agents. Point Claude Code,
Cursor, or any other MCP-compatible AI assistant at AgentGuard instead of a
raw filesystem server, and every tool call it makes passes through a
deterministic policy gate first — scoped to a sandbox directory, allowlisted
by tool, with destructive actions denied until a human approves them.

Telling an agent "you're read-only" in a prompt doesn't make it read-only —
the only thing that does is a control underneath the prompt that the agent
can't talk its way around. AgentGuard is that control, built as something
you can actually run.

## Status

Phase 1 (core proxy + tool allowlist + sandbox containment) — **shipped**.
See [docs/PRD.md](docs/PRD.md) and [Plan_agentguard.md](Plan_agentguard.md)
for the full roadmap and phase status.

## How it works

```
AI agent (Claude Code, Cursor, …)
        │  MCP protocol (stdio)
        ▼
AgentGuard (this repo)
        │  PolicyMiddleware checks every tools/call
        │  against policy.yaml BEFORE it runs
        ▼
read_file / write_file / delete_file
        │  (sandboxed to ./sandbox, re-checked again here too)
        ▼
   audit.log  (every decision, allowed or denied)
```

The policy check lives in MCP protocol middleware
(`proxy/app/middleware.py`), not hand-coded inside each tool function — so
every tool registered on the server passes through the same gate
automatically, and a future tool can't accidentally ship without policy
coverage.

## Quick start

```bash
cd proxy
python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q          # 11 tests, incl. 3 real MCP-protocol integration tests
.venv/bin/python -m app.server         # run the server directly (stdio)
```

## Wiring into Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "/absolute/path/to/agentguard/proxy/.venv/bin/python",
      "args": ["-m", "app.server"],
      "cwd": "/absolute/path/to/agentguard/proxy"
    }
  }
}
```

Claude Code (or Cursor, using its own MCP config format) will then see
`read_file`, `write_file`, and `delete_file` as tools, all enforced by
`proxy/policy.yaml`. Try asking it to write a file outside `proxy/sandbox/`
— the call gets DENIED by AgentGuard, not by the agent's own good behavior.

## Why this design

Full reasoning and the threat model this is built against:
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/PRD.md](docs/PRD.md).
