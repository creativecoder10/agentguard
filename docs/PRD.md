# PRD — AgentGuard: a policy-enforcing MCP proxy for AI coding agents

**Status:** Phases 0, 1, 1b and 2a shipped. Phase 2b (approval flow) and later not started. See [§7](#7-phase-status).
**Owner:** Deepesh Dang
**Last updated:** 2026-10-05 (2a)

## 1. Problem

AI coding agents (Claude Code, Cursor, and others) are increasingly given
real tool access — filesystem writes, shell commands, cloud API calls —
through system prompts that say things like "you may only read files" or
"never delete anything without asking." That instruction lives entirely at
the prompt layer: a sufficiently manipulated agent (via prompt injection
from untrusted content it reads) or a simple model error can ignore it, and
nothing underneath stops the resulting tool call from executing. Teams
adopting agentic development today mostly have no enforcement layer between
"the agent decided to do X" and "X happened."

## 2. Goal

Build a working MCP (Model Context Protocol) proxy that any MCP-compatible
AI coding assistant can be pointed at instead of a raw tool server. Every
tool call passes through a deterministic policy gate — tool allowlisting,
sandbox path containment, blocked file types, destructive-action denial —
enforced in code the agent cannot talk its way around, with every decision
logged. The gate works in both directions: what the agent *asks to do*
(input-side policy) and what a tool *hands back* into the agent's context
(output-side scanning — secrets redacted, prompt-injection text fenced off
or blocked). This is a portfolio-grade demonstration of applying AppSec
fundamentals (least privilege, defense-in-depth, never trust the
client/prompt layer) to the agentic-AI security problem, not a production
security product.

### Non-goals

- Not a general-purpose MCP gateway for arbitrary downstream servers in
  Phase 1 — ships its own three file tools first; proxying to an *external*
  MCP server is a later phase.
- Not multi-tenant or hosted — single developer, single policy file, local
  stdio only.
- Not a replacement for cloud-level IAM — AgentGuard is the tool-call gate;
  scoped cloud credentials (Phase 4) are a separate, complementary layer.

## 3. Users

Primary audience is the project's author and the people evaluating this
work (interviewers, reviewers), same framing as vigilant-engine. The
secondary, aspirational user is any developer running an MCP-compatible AI
coding agent who wants a policy gate in front of it without switching
tools.

## 4. Requirements by area

Each area below is a phase in [Plan_agentguard.md](../Plan_agentguard.md);
that file is the source of truth for granular task status.

### 4.1 Threat model — **shipped**

| Requirement | Decision |
| --- | --- |
| Identify what AgentGuard actually protects against before writing enforcement code | [docs/THREAT_MODEL.md](THREAT_MODEL.md) — STRIDE analysis of the agent→tool boundary |
| Mitigations must be traceable to a specific test, not just asserted | Every STRIDE row cites the test(s) that prove it, or is explicitly marked deferred |

### 4.2 Core proxy (`proxy/`) — **shipped**

| Requirement | Decision |
| --- | --- |
| Policy enforcement must sit at the protocol layer, not inside each tool | `PolicyMiddleware` (`app/middleware.py`) intercepts every `tools/call` MCP request via the SDK's `ServerMiddleware` hook, before any tool function runs |
| Policy must be data, not code — changeable without a redeploy | `policy.yaml`: tool allowlist, per-tool risk tier, blocked extensions, sandbox root — loaded by `app/config.py` |
| Path traversal must be structurally impossible, not filtered by string-matching `..` | `_resolve_within_sandbox()` resolves the full path first, *then* checks containment via `Path.relative_to()` — nothing left to sneak past after resolution |
| Destructive actions must never execute silently | `delete_file` tagged `risk: destructive`; hard-denied until Phase 2 adds a real approval flow |
| Defense-in-depth must be real, not just a slide | Sandbox containment checked twice independently: once in middleware, once again inside each tool function (`_sandbox_path()` in `app/server.py`) |
| Every decision must be logged | `AuditLogger` writes one JSON line per ALLOW/DENY to `audit.log` — verified with real log entries from a live run (§4.3) |
| Must work with a real MCP client over the real protocol, not just in-process function calls | 3 integration tests (`tests/test_server_integration.py`) spawn the actual server as a subprocess and drive it with the real `mcp` SDK's `ClientSession`/`stdio_client` |

### 4.3 Verification — **shipped**

| Requirement | Decision |
| --- | --- |
| Unit coverage of the policy engine | 8 unit tests (`tests/test_policy.py`): sandboxed read, path traversal (relative and absolute), unlisted tool, blocked extension, destructive-tool denial, missing argument, nested-path write |
| End-to-end proof over the real protocol | 3 integration tests, run against a real subprocess server — **all 11 tests pass** |
| Verified against a real run, not just "should work" | Captured real `audit.log` output from the integration test run: `ALLOW write_file`, `DENY read_file ../../../../etc/passwd — resolves outside the sandbox root`, `DENY delete_file — requires human approval` |
| Test isolation | Integration tests write an isolated `policy.yaml`/`audit.log` per test run via `AGENTGUARD_POLICY_PATH`/`AGENTGUARD_AUDIT_PATH` env overrides — the real `proxy/sandbox/` and `proxy/audit.log` are never touched by the test suite (confirmed: both are absent from disk after a full test run) |

### 4.4 Integration with a real AI coding agent — **documented, not yet manually driven end-to-end**

| Requirement | Decision |
| --- | --- |
| Must be wireable into Claude Code with no code change on the agent side | `.mcp.json` snippet in [README.md](../README.md) — standard MCP stdio server config |
| Not yet done | A manual session actually driving Claude Code against AgentGuard's `.mcp.json` config, screenshotted, showing a real denial in the agent's own transcript — tracked as the first item of the next phase |

### 4.5 Reference agent harness & output-side scanning (Phase 1b) — **shipped**

Why this phase exists: everything up to 4.4 proves the gate holds when a
*client* sends a bad call. It doesn't show *why* an agent would send one,
or what happens to the data flowing back. Phase 1b adds the missing half:
a minimal agent harness that drives real Claude through AgentGuard, the
output-side checks a harness needs, and a reproducible indirect
prompt-injection demo.

| Requirement | Decision |
| --- | --- |
| Show what a harness actually is, not just use one | `harness/agent.py` — a hand-written ~100-line agent loop on the Claude API (`claude-opus-5-5`): send messages + tool schemas → run each `tool_use` → append results → repeat. Deliberately not the SDK's tool runner, so every control point is visible |
| The harness must not be the security boundary | The harness forwards every call to AgentGuard over real MCP (stdio) and makes no allow/deny decision itself — swap in Claude Code or Cursor and the same gate applies |
| Harness control points | Hard turn ceiling (`MAX_TURNS`); never execute tool calls from a `refusal` or `max_tokens` turn (a truncated `tool_use` can carry half-written arguments); full assistant content appended unchanged; all tool results for a turn returned in one message; server-side refusal fallback enabled |
| Tool output is untrusted input | `PolicyMiddleware._scan_result()` scans every ALLOWed result before it leaves the proxy (`app/result_guard.py`) |
| Secrets in tool output never reach the model | Redacted to `[REDACTED:<kind>]` — AWS keys, private-key blocks, GitHub/Slack/Anthropic tokens, `PASSWORD=`-style assignments |
| Injection text is visible as untrusted, or withheld | Pattern signals (instruction override, role reassignment, fake `system:` turns, hidden Unicode). `on_injection: flag` fences the output in `<untrusted_tool_output>` markers (an attacker-supplied closing marker is neutralised first); `on_injection: block` replaces it with an error. Hidden Unicode is stripped outright |
| No second copy leaks | The MCP SDK returns a tool's value as both `content` and `structuredContent` — both are scanned and fenced, or the secret leaks one field over (found while building this, now covered by an integration test) |
| Every output-side decision is auditable | `audit.log` ALLOW entries carry `findings: {secrets_redacted, injection_signals, action}` |
| Demo reproducible by anyone, free | `harness/demo_injection.py --scripted` plays a *fully* hijacked model (no API key, no spend); `--live` runs real Claude against the same poisoned file |
| Verified, not asserted | 12 new proxy tests (10 unit, 2 real-protocol) + 7 harness tests driving the loop over real MCP against a real AgentGuard subprocess — **30 tests total, all passing** |

**Honest limit, stated up front:** injection detection is pattern matching
and will miss a rephrased payload — the demo's own payload slipped past the
first version of the override pattern because of a line break. It is a
tripwire and audit signal. The security boundary is still the input-side
gate: in the demo, a model that obeys the injection completely still can't
delete, can't leave the sandbox, and never sees the planted key.

**Residual risk found here, closed in 2a (§4.6):** a hijacked agent could
still make *in-policy* calls for the attacker — the demo's `exfil.txt`
write inside the sandbox was allowed.

### 4.6 Session taint & task-scoped writes (Phase 2a) — **shipped**

| Requirement | Decision |
| --- | --- |
| After untrusted input, state changes need a human | `app/taint.py` — a session is tainted by its first untrusted read; from then on tools whose risk is in `taint.blocks_risk` (default `write`, `destructive`) are denied with the taint reason, until the Phase 2b approval flow can turn that into a prompt. Taint is sticky: untrusted text never leaves the model's context, so the restriction doesn't either |
| Must hold when detection misses | Taint by **source**: reading a path matching `taint.untrusted_sources` taints regardless of content. Taint by **signal** (result_guard flagged the output) is an extra trigger, not the only one. Tested with a payload written to evade every pattern |
| Shrink what an agent can touch before anything goes wrong | `writable_paths` — task-scoped write allowlist; the launcher sets it per task (`AGENTGUARD_WRITABLE_PATHS`, or `server_params(writable_paths=...)` in the harness) |
| Session = process | Over stdio one proxy process serves one client, so taint lives on the middleware instance. An HTTP transport would need it keyed by session id — noted in code |
| Auditable | the call that taints the session logs `findings.session_tainted`; every later denial carries the reason |
| Verified | 14 new proxy tests (8 taint unit, 3 writable_paths unit, 3 real-protocol) + 3 harness tests — **47 tests total, all passing** |

**Trade-offs, stated honestly:**
- *Usability:* a tainted session also can't make its **legitimate** write
  (e.g. `summary.md` after reading poisoned notes). That's the price of
  failing closed until Phase 2b approval exists.
- *Coverage:* taint-by-source is only as good as the source labels. A
  scanner-evading payload in a path *not* marked untrusted still doesn't
  taint — `writable_paths` is the backstop that limits what such a session
  can write.

## 5. Known gap: human-in-the-loop approval

Phase 1 handles the "destructive" risk tier by hard-denying every call,
which is correct but incomplete — a real product needs destructive actions
to be *approvable*, not just blocked forever. This is explicitly Phase 2,
not quietly deferred: `policy.py`'s own denial message says so
("approval flow not implemented yet — Phase 2"), so the gap is visible at
runtime, not just in this doc.

## 6. Out of scope for now

- Proxying to a real external MCP server (filesystem, git, DB) instead of
  AgentGuard's own built-in tools — Phase 1 ships the tools itself to prove
  the enforcement pattern first, with fewer moving parts.
- Rate limiting / circuit breaking (STRIDE "D" row) — no cost/compute
  pressure yet with three local file tools; revisit once a real downstream
  service is proxied.
- Non-MCP pipelines (OpenAI/LangChain function-calling) — MCP first, since
  it's the interoperability layer Claude Code and Cursor already share.
- The harness as a product — `harness/` is a reference client and demo
  rig, not a competitor to Claude Code; real users point their own agent
  at the proxy.
- ML-based injection classifiers — pattern matching is enough to prove the
  output-side control point and its audit trail; a classifier slots into
  `result_guard.py` later without changing the middleware.
- Packaging as an installable pip/npm artifact — current target is "clone
  and run," packaging comes once the feature set is stable enough to be
  worth versioning.

## 7. Phase status

Full task-level checklist: [Plan_agentguard.md](../Plan_agentguard.md).

| Phase | Scope | Status |
| --- | --- | --- |
| 0 — Threat model & scope | STRIDE analysis, MVP cut decided (own tools, not proxy-to-external first) | **Shipped** |
| 1 — Core proxy | MCP server, `PolicyMiddleware`, sandbox containment (2 layers), tool allowlist, blocked extensions, destructive hard-deny, audit logging, 11 passing tests incl. 3 real-protocol integration tests | **Shipped** |
| 1b — Reference harness & output-side scanning | Hand-written agent loop on the Claude API driving AgentGuard over MCP; tool-result secret redaction + injection flag/block; scripted + live injection demo; 30 passing tests | **Shipped** |
| 2a — Session taint & task-scoped writes | Untrusted read (by source or injection signal) taints the session → write/destructive denied; per-task `writable_paths` | **Shipped** |
| 2b — Human-in-the-loop approval | Turn the hard denies (destructive, tainted-session writes) into an interactive approval gate (terminal prompt for MVP) | **Not started** |
| 3 — Monitoring & rate limiting | Simple dashboard over `audit.log`, rate limit / circuit breaker per session | **Not started** |
| 4 — Scoped credentials | Issue short-lived, scoped credentials per tool call (e.g. AWS STS) instead of trusting a static key | **Not started** |
| 5 — Prompt-injection test harness | Adversarial test suite proving the gate holds under a simulated injection attempt, TenantGuard-style | **Not started** — first scenario (poisoned file, fully hijacked model) delivered in 1b |
| 6 — Package as shippable product | pip/Docker packaging, config generator for `.mcp.json`/Cursor, self-scan with Semgrep/gitleaks in CI | **Not started** |
| 7 — Broader pipeline support (stretch) | OPA/Rego policy engine; thin adapter for non-MCP (OpenAI/LangChain) tool-calling pipelines | **Not started** |

## 8. Success criteria

- A path-traversal attempt is denied at the real MCP protocol boundary,
  proven by an integration test using a real client — **met**.
- A destructive action never executes without an explicit allow — **met**
  (currently via hard-deny; Phase 2 replaces this with real approval).
- A model that fully obeys an indirect prompt injection still can't
  delete, escape the sandbox, or see a planted secret — **met**
  (`harness/tests/test_agent_loop.py`, scripted hijacked model over real
  MCP).
- After reading untrusted data — including a payload the scanner misses —
  a session can't change anything without approval — **met**
  (`test_untrusted_source_taints_even_when_scanner_sees_nothing`,
  `test_scanner_evading_payload_from_untrusted_source_still_locks_writes`).
- Every non-trivial design decision (middleware-vs-per-tool enforcement,
  own-tools-vs-proxy MVP cut, two-layer sandbox check) is traceable to a
  written reason — **met**, tracked in [Plan_agentguard.md](../Plan_agentguard.md).

## References

- [docs/THREAT_MODEL.md](THREAT_MODEL.md) — STRIDE analysis
- [harness/agent.py](../harness/agent.py) — reference agent harness;
  [harness/demo_injection.py](../harness/demo_injection.py) — injection demo
- [Plan_agentguard.md](../Plan_agentguard.md) — phased task checklist
- [README.md](../README.md) — quick start and Claude Code wiring
- Project origin: interview-prep discussion on agentic AI security,
  logged in vigilant-engine's `notes/APPSEC_INTERVIEW_QA_MASTER.md`
  ("Agentic AI security — prompt-level instructions vs. system-level
  controls")
