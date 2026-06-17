# Architecture

AgentFence is organized as a local control plane. Agents connect through wrappers, proxies, or SDK integrations. Policy decisions are deterministic and auditable.

```text
Agent
  Claude Code / Codex / Custom MCP Agent
        |
        v
AgentFence CLI / MCP Proxy / SDK
        |
        v
AgentFence Daemon
        |
        +-- Policy Engine
        +-- Shell Classifier
        +-- MCP Decision Layer
        +-- Audit Store
        +-- Desktop UI
```

## Components

### Policy Engine

The policy engine lives in `crates/agentfence-policy`. It owns the policy data model, policy loading, default policy generation, shell decisions, filesystem decisions, network decisions, MCP decisions, skill decisions, policy bundles, and JSON schema generation.

### CLI

The CLI lives in `crates/agentfence-cli`. It is the first enforcement entry point:

- `init` creates a policy.
- `check` evaluates shell command risk and policy decisions.
- `run` checks a command, evaluates discovered network domains, asks for approval when needed, writes an audit event, and only then executes.
- `logs` reads the local SQLite audit store.
- `daemon start`, `daemon status`, `daemon stop`, and `daemon restart` manage the local daemon lifecycle.
- `approvals list` and `approve` inspect and resolve daemon approval requests from the terminal.
- `mcp check` evaluates MCP access decisions.
- `integrations install` writes agent wrapper scripts and can optionally register the wrapper directory on the user PATH.

### Daemon

The daemon lives in `crates/agentfence-daemon`. It provides local HTTP APIs for the desktop app and future agent integrations:

- `GET /health`
- `POST /shutdown`
- `GET /policy`
- `PUT /policy`
- `POST /policy/validate`
- `POST /policy/ask`
- `GET /policy/presets`
- `GET /policy/bundle`
- `POST /policy/bundle/verify`
- `POST /policy/bundle/import`
- `GET /audit?limit=50&actor=codex&decision=deny&action=shell.exec`
- `GET /audit/export?format=csv`
- `GET /approvals?status=pending`
- `GET /approvals/:id`
- `POST /approvals`
- `POST /approvals/:id/resolve`
- `POST /shell/check`
- `POST /filesystem/check`
- `POST /network/check`
- `POST /skill/check`
- `POST /mcp/check`
- `POST /simulate/shell`

### Audit Store

The audit store lives in `crates/agentfence-audit` and writes local SQLite records. Events include actor, action, subject, decision, risk, reason, matched rule, working directory, and metadata. Guarded shell execution and MCP proxy calls both write audit events when policy audit logging is enabled. Recent event reads can be filtered by exact actor, decision, and action matches.

Command subjects and reasons are passed through a lightweight redactor before being written, covering common token, password, API key, GitHub token, OpenAI-style key, and AWS access key shapes.

### Approval Queue

The approval queue lives in `crates/agentfence-approval` and is hosted in memory by the daemon. Any daemon check that evaluates to `ask` creates a pending approval request. The desktop UI reads `/approvals?status=pending` and resolves requests through `/approvals/:id/resolve`.

### Desktop UI

The desktop app lives in `apps/desktop`. It uses Tauri, React, TypeScript, and Vite. The current UI has dashboard, approval, audit, policy, MCP, skill, export, and settings surfaces. The policy editor validates JSON, shows a line-level diff against the last loaded or saved policy, can review and apply selected JSON Patch operations, can apply daemon-generated audit suggestions, and includes structured quick-rule controls for shell commands, network domains, and skills before changes are saved. Settings can point the UI at a different local daemon endpoint, start or stop the default local daemon, and test local approval notifications; by default it checks daemon health through `http://127.0.0.1:37421/health`.

### Website

The public website lives in `apps/web`. It uses Next.js and contains the marketing homepage, download page, security page, and initial documentation pages.

### Policy Assistant

The policy assistant starts as a deterministic proposal generator in `crates/agentfence-policy`. It converts common natural-language permission requests into JSON Patch operations and intentionally does not apply them automatically. The CLI also exposes a reusable policy rule library through `agentfence policy library`, combines, signs, verifies, and imports review presets through `agentfence policy review-preset`, and scans recent audit observations to suggest exact allow rules for repeatedly approved `ask` decisions through `agentfence policy suggest` and `GET /policy/suggestions`.

### Policy Simulator

The simulator evaluates hypothetical actions without creating approval requests or writing audit events. The first implementation supports shell commands through `agentfence simulate shell -- <command>` and `POST /simulate/shell`, including effective decisions that combine shell and extracted network-domain policy.

### Policy Bundles

Policy bundles are portable team-policy artifacts. They include the policy body, metadata, a SHA-256 digest, and optional Ed25519 signature. The daemon can export, verify, and import bundles through local endpoints, while the CLI exposes key generation, signing, verification, and import workflows for scripts.

## Current Enforcement Boundary

The current implementation enforces shell commands launched through `agentfence run`, commands typed into the line-oriented guarded shell `agentfence shell`, and submitted lines in the PTY-backed shell MVP `agentfence shell --pty`. This is useful for explicit wrapper flows and for interactive local sessions where every entered command should be checked:

```bash
agentfence run -- codex
agentfence run -- claude
agentfence run -- npm test
agentfence shell --actor codex
agentfence shell --pty --actor codex
```

The initial MCP stdio proxy is available through `agentfence mcp proxy`, and a scoped HTTP JSON-RPC/SSE proxy is available through `agentfence mcp http-proxy`. They inspect client-to-server JSON-RPC calls for `tools/call`, `resources/read`, and `prompts/get`, then block denied or rate-limited requests before they reach the upstream server. They also track `tools/list`, `resources/list`, and `prompts/list` requests so denied entries can be filtered out of complete upstream JSON list responses, chunked JSON list responses, and JSON-RPC responses carried in SSE `data:` events. The HTTP proxy passes through GET/SSE and other streaming responses after request-level checks.

Guarded shell commands also extract URL-like arguments and common Git/SSH remotes, then evaluate those domains against `network` policy before execution. The PTY shell uses a real pseudo-terminal child process and a small terminal-query response broker, but still checks submitted command lines rather than raw key events. Future milestones should add raw-mode PTY brokering for full-screen TUI programs, external tool broker adapters, deeper filtering for open-ended non-JSON MCP streams, and optional OS-level or proxy-level network/filesystem controls.

The shell classifier is intentionally conservative around commands that can hide or amplify follow-up actions. Nested shell execution (`bash -lc`, `cmd /c`, `powershell -Command`, `node -e`, `python -c`), encoded PowerShell, package publishing, infrastructure apply/destroy commands, and repository history rewrites are elevated before policy matching. This improves wrapper-mode and PTY-MVP safety while the deeper raw terminal interception design remains open.
