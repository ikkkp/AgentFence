# AgentFence

Local permissions and tool governance for AI coding agents.

AgentFence is a local-first permission gateway for Claude Code, Codex, and custom MCP-based agents. It provides deterministic policy enforcement for shell commands, MCP tools, skills, filesystem boundaries, network preferences, human approvals, and audit logs.

## Current Status

This repository now contains the first implementation slice from the roadmap:

- Rust workspace with CLI, daemon, policy, shell classifier, MCP decision, and audit crates.
- `agentfence` CLI with policy initialization, validation, shell checks, guarded command execution, simulation, MCP checks, MCP stdio proxying, MCP rate limits, and audit log reads.
- `agentfenced` local HTTP daemon with health, policy, approval queue, audit, shell check, filesystem, network, skill, and MCP check endpoints.
- `agentfence.policy.json` plus schema and Codex/Claude Code examples.
- Tauri + React desktop UI shell for dashboard, approvals, policy preview, policy diff review, audit, MCP, and skill controls.
- Next.js website shell with homepage, download, security, and docs pages.
- CI workflow for Rust and web verification.
- Release workflow for CLI, daemon, and Tauri desktop artifacts.

## Repository Layout

```text
apps/
  desktop/              Tauri + React desktop client
  web/                  Next.js website and docs
crates/
  agentfence-audit/     SQLite audit log store
  agentfence-cli/       agentfence CLI binary
  agentfence-daemon/    local HTTP daemon
  agentfence-mcp/       MCP access decision primitives
  agentfence-policy/    policy types, loading, schema, decisions
  agentfence-shell/     command risk classification
docs/                   architecture and implementation docs
examples/               Codex and Claude Code policy examples
schemas/                policy JSON schema
```

## Quickstart

Validate the default policy:

```bash
cargo run --bin agentfence -- policy validate agentfence.policy.json
```

Check a shell command:

```bash
cargo run --bin agentfence -- check -- git status
cargo run --bin agentfence -- check -- npm install
cargo run --bin agentfence -- check -- rm -rf /
```

Run a guarded command:

```bash
cargo run --bin agentfence -- run -- git status --short
```

Read audit logs:

```bash
cargo run --bin agentfence -- logs --limit 10
```

Start the local daemon:

```bash
cargo run --bin agentfenced -- --listen 127.0.0.1:37421
```

Trigger and inspect the approval queue:

```bash
curl -X POST http://127.0.0.1:37421/shell/check \
  -H "content-type: application/json" \
  -d '{"actor":"codex","command":["npm","install"]}'

curl http://127.0.0.1:37421/approvals?status=pending
```

Run the desktop UI:

```bash
pnpm install
pnpm --filter @agentfence/desktop dev
```

Run the website:

```bash
pnpm --filter @agentfence/web dev
```

## CLI Commands

```bash
agentfence init
agentfence init --preset strict
agentfence policy validate agentfence.policy.json
agentfence policy schema
agentfence policy ask "allow tests but ask before dependency installs"
agentfence policy apply --yes "deny production deploy"
agentfence policy bundle export --output team.bundle.json
agentfence policy bundle keygen --output bundle-key.json
agentfence policy bundle export --output signed.bundle.json --key bundle-key.json
agentfence policy bundle verify team.bundle.json
agentfence policy bundle import signed.bundle.json --yes --require-signature
agentfence check -- git status
agentfence simulate shell -- git status https://transfer.sh/file
agentfence run -- git status --short
agentfence run --actor codex -- codex
agentfence run --actor claude-code -- claude
agentfence logs --limit 20
agentfence audit export --format csv --output audit.csv
agentfence approvals list
agentfence approve <approval-id> --decision allowed
agentfence filesystem check --operation read --path ~/.ssh/id_rsa
agentfence network check --domain github.com
agentfence skill check --name code-review
agentfence mcp check --server github --kind tool --name create_pull_request
agentfence mcp proxy --server github -- node path/to/github-mcp-server.js
agentfence mcp proxy --server github --audit .agentfence/audit.sqlite -- node path/to/server.js
```

## Security Model

AgentFence does not rely on an agent prompt as the security boundary. The policy engine evaluates requests before execution or forwarding. The current implementation enforces commands launched through `agentfence run`, checks URL-like and common Git/SSH remotes in guarded commands against network policy, and enforces MCP stdio calls through `agentfence mcp proxy`. Deeper shell interception, broader MCP transports, full network proxying, and OS-level filesystem controls remain roadmap hardening items.

Audit events redact common secret shapes such as `token=...`, `password=...`, GitHub personal access tokens, OpenAI-style `sk-...` tokens, and AWS access key IDs before writing command subjects, reasons, and metadata strings to SQLite.

Natural-language policy management currently generates JSON Patch proposals only. The assistant path does not apply changes or bypass deterministic enforcement by itself.

The MCP stdio proxy enforces `tools/call`, `resources/read`, and `prompts/get`, and filters denied entries from `tools/list`, `resources/list`, and `prompts/list` responses. `ask` decisions default to deny in stdio proxy mode, can be allowed for trusted testing with `--ask-mode allow`, or can wait on the daemon approval queue with `--ask-mode queue`.

MCP server policies can include `rateLimit` windows. Calls over the limit receive an MCP error response and are not forwarded upstream.

MCP proxy decisions are written to the configured audit store when policy audit logging is enabled.

Policy bundles include a SHA-256 digest for integrity verification and support Ed25519 signatures for team policy distribution.

## Development

Run Rust checks:

```bash
cargo fmt --check
cargo test
```

Run frontend checks:

```bash
pnpm typecheck
pnpm build
```

Build release artifacts:

```bash
cargo build --release --bin agentfence --bin agentfenced
pnpm --filter @agentfence/desktop tauri:build
```

See [docs/release.md](./docs/release.md) for tag-driven packaging.

## Roadmap

See [ROADMAP.md](./ROADMAP.md).

Integration profiles are documented in [docs/integrations.md](./docs/integrations.md), with machine-readable wrapper examples in [examples/integrations](./examples/integrations).
