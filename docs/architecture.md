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
- `approvals list` and `approve` inspect and resolve daemon approval requests from the terminal.
- `mcp check` evaluates MCP access decisions.

### Daemon

The daemon lives in `crates/agentfence-daemon`. It provides local HTTP APIs for the desktop app and future agent integrations:

- `GET /health`
- `GET /policy`
- `PUT /policy`
- `POST /policy/validate`
- `POST /policy/ask`
- `GET /policy/presets`
- `GET /policy/bundle`
- `POST /policy/bundle/verify`
- `POST /policy/bundle/import`
- `GET /audit?limit=50`
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

### Audit Store

The audit store lives in `crates/agentfence-audit` and writes local SQLite records. Events include actor, action, subject, decision, risk, reason, matched rule, working directory, and metadata.

Command subjects and reasons are passed through a lightweight redactor before being written, covering common token, password, API key, GitHub token, OpenAI-style key, and AWS access key shapes.

### Approval Queue

The approval queue lives in `crates/agentfence-approval` and is hosted in memory by the daemon. Any daemon check that evaluates to `ask` creates a pending approval request. The desktop UI reads `/approvals?status=pending` and resolves requests through `/approvals/:id/resolve`.

### Desktop UI

The desktop app lives in `apps/desktop`. It uses Tauri, React, TypeScript, and Vite. The current UI has dashboard, approval, audit, policy, MCP, and skill surfaces. It checks daemon health through `http://127.0.0.1:37421/health`.

### Website

The public website lives in `apps/web`. It uses Next.js and contains the marketing homepage, download page, security page, and initial documentation pages.

### Policy Assistant

The policy assistant starts as a deterministic proposal generator in `crates/agentfence-policy`. It converts common natural-language permission requests into JSON Patch operations and intentionally does not apply them automatically.

### Policy Bundles

Policy bundles are portable team-policy artifacts. They include the policy body, metadata, a SHA-256 digest, and optional Ed25519 signature. The daemon can export, verify, and import bundles through local endpoints, while the CLI exposes key generation, signing, verification, and import workflows for scripts.

## Current Enforcement Boundary

The current implementation enforces shell commands launched through `agentfence run`. This is useful for explicit wrapper flows:

```bash
agentfence run -- codex
agentfence run -- claude
agentfence run -- npm test
```

The initial MCP stdio proxy is available through `agentfence mcp proxy`. It inspects client-to-server JSON-RPC calls for `tools/call`, `resources/read`, and `prompts/get`, then blocks denied requests before they reach the upstream server. It also tracks `tools/list`, `resources/list`, and `prompts/list` requests so denied entries can be filtered out of upstream list responses.

Guarded shell commands also extract URL-like arguments and common Git/SSH remotes, then evaluate those domains against `network` policy before execution. Future milestones should add deeper pseudo-shell integration, broader MCP transport support, external tool broker adapters, and optional OS-level or proxy-level network/filesystem controls.
