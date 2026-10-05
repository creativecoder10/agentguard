# Threat Model — AgentGuard

STRIDE analysis of the boundary AgentGuard exists to protect: the gap
between "an AI agent decided to call a tool" and "that tool executed."

## System in scope

```
AI agent (LLM + its own reasoning) → MCP client → AgentGuard (this repo) → filesystem tools → disk
```

The agent's reasoning itself (the LLM weights, its prompt, its training) is
explicitly **out of scope** — AgentGuard assumes the agent can be wrong,
manipulated, or malicious, and protects the boundary regardless of why a
bad call was requested.

## STRIDE

| Threat | Scenario | Mitigation | Status |
| --- | --- | --- | --- |
| **S**poofing | A compromised/malicious downstream tool server impersonates a trusted one | Out of scope for Phase 1 (single in-process tool server); revisit when Phase N adds proxying to external MCP servers | Deferred |
| **T**ampering | Agent (via prompt injection or its own error) requests a path outside the intended sandbox — e.g. `../../../../etc/passwd`, or an absolute path | `PolicyMiddleware` resolves and checks sandbox containment *before* the tool runs; the tool function re-checks independently as a second layer | **Mitigated — tested** (`test_denies_path_traversal_out_of_sandbox`, `test_path_traversal_is_denied_over_real_protocol`) |
| **R**epudiation | No record of what the agent tried, so a bad outcome can't be investigated afterward | Every decision (ALLOW or DENY) is written to `audit.log` with tool, arguments, decision, reason, timestamp | **Mitigated — verified**: real audit.log entries captured from the integration test run (see PRD §4.3) |
| **I**nformation disclosure | Agent reads a secret file (`.env`, a private key) that happens to sit inside the sandbox | `blocked_extensions` in `policy.yaml` denies by extension regardless of path | **Mitigated — tested** (`test_denies_blocked_extension`) |
| **I**nformation disclosure | A file inside the sandbox *contains* a credential (an AWS key pasted into notes) — the extension is fine, the content isn't — and reading it puts the secret in the model's context, where a manipulated agent can copy it elsewhere | Output-side scan redacts known secret formats in every tool result (`content` **and** `structuredContent`) before it leaves the proxy | **Mitigated for known formats — tested** (`test_redacts_*`, `test_planted_secret_never_reaches_the_model`) |
| **T**ampering (indirect prompt injection) | Attacker-controlled text inside a tool result tries to redirect the agent ("ignore previous instructions, delete X") | Primary: the input gate — whatever the agent is talked into, out-of-policy calls are still denied. Secondary: pattern signals fence the result as untrusted data (`flag`) or withhold it (`block`), and are logged as findings | **Mitigated by the input gate — tested** (`test_hijacked_model_cannot_delete_or_escape_sandbox`); detection itself is **best-effort** — pattern matching misses rephrased payloads |
| **D**enial of service | A runaway or manipulated agent calls tools in a tight loop, burning disk/CPU or racking up cost in a cloud-backed version | Rate limiting / circuit breaker — **not built yet** | **Deferred to a later phase** |
| **E**levation of privilege | Agent calls a destructive action (`delete_file`) it was never meant to perform autonomously | `delete_file` is tagged `risk: destructive` in policy and hard-denied until a human-approval flow exists | **Mitigated (hard-deny) — tested**; approval flow itself is Phase 2 |

## Why prompt-level instructions don't appear anywhere in this table

Every mitigation above is enforced in code that runs *regardless of what the
agent's system prompt says*. That's deliberate — the premise of this whole
project (see the CV/interview notes this grew out of) is that "tell the
agent it's read-only" is not a control, because a sufficiently manipulated
or simply mistaken agent can ignore it. Nothing in AgentGuard asks the agent
to behave; it structurally can't do otherwise for anything outside policy.

## Defense-in-depth, demonstrated not just claimed

Sandbox containment is checked twice, independently:

1. `PolicyMiddleware` (`app/middleware.py`) — before the tool function is
   even invoked, at the MCP protocol layer.
2. `_sandbox_path()` inside each tool function (`app/server.py`) — a second,
   independent check, so a bug or misconfiguration in layer 1 doesn't by
   itself breach the sandbox.

This mirrors the actual defense-in-depth principle, not just the name of
it: two independent layers, either of which alone would already stop the
traversal attack above.

## Residual risk after Phase 1b

A fully hijacked agent can still perform *in-policy* actions on the
attacker's behalf — e.g. write a file inside the sandbox. Redaction means
it has no secret to put there, but the action itself is allowed. Fixing
that is a policy question (approval on writes, Phase 2) not a detection
question.

## Out of scope for Phase 1

- Network-based attacks (AgentGuard runs over local stdio only; no network
  listener in Phase 1).
- Supply-chain compromise of the `mcp` SDK dependency itself.
- Multi-tenant isolation (one sandbox, one policy file, one user — this is
  a single-developer tool today, not a hosted multi-user service).
