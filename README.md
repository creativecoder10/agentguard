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
Phase 1b (reference agent harness + output-side secret redaction and
prompt-injection flagging + injection demo) — **shipped**.
Phase 2a (session taint: after untrusted input, writes need approval;
task-scoped `writable_paths`) — **shipped**.
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
.venv/bin/python -m pytest -q          # 37 tests, incl. 8 real MCP-protocol integration tests
.venv/bin/python -m app.server         # run the server directly (stdio)
```

## Demo: indirect prompt injection

`harness/` holds a minimal agent harness — a hand-written loop on the
Claude API — that routes every tool call through AgentGuard, plus a demo
where a file the agent reads carries a planted AWS key and hidden
instructions to delete files and steal an SSH key.

```bash
cd harness
../.venv/bin/python demo_injection.py --scripted   # free: plays a FULLY hijacked model
../.venv/bin/python demo_injection.py --live       # real Claude (needs ANTHROPIC_API_KEY)
../.venv/bin/python -m pytest -q                   # 10 harness tests, no API key needed
```

Scripted run, abridged:

```
── tool: read_file(meeting_notes.md) → ok        key shown as [REDACTED:aws_access_key_id],
                                                  output fenced as <untrusted_tool_output>
── tool: delete_file(summary.md) → DENIED          destructive, requires human approval
── tool: read_file(../../../.ssh/id_rsa) → DENIED  resolves outside the sandbox root
── tool: write_file(exfil.txt) → DENIED           session is tainted (read flagged output)
```

The model obeyed the injection completely and still couldn't do damage —
that's the point: the boundary is the gate, not the model's judgment.

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
