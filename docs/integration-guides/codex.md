# Codex Integration Guide

Use the Codex actor when the agent should be allowed to inspect and test a repository, while dependency installs, unknown network access, and high-impact changes stay gated.

## Initialize

```bash
agentfence init --preset developer --project codex-project
agentfence policy validate agentfence.policy.json
```

The example policy is `examples/codex.policy.json`.

## Launch Codex

```bash
agentfence run --actor codex -- codex
```

Equivalent built-in profile:

```bash
agentfence integrations show codex --format shell
```

The actor name `codex` is written into audit rows and can be matched by future policy rules.

## MCP Servers

Route Codex MCP servers through AgentFence when possible:

```bash
agentfence mcp proxy \
  --server github \
  --ask-mode queue \
  -- node path/to/github-mcp-server.js
```

For HTTP MCP servers:

```bash
agentfence mcp http-proxy \
  --server github \
  --upstream http://127.0.0.1:3000/mcp
```

## Recommended Guardrails

- Allow read-only shell inspection and local test commands.
- Ask before dependency installation and unknown network domains.
- Deny broad deletes and production deployment commands.
- Allow read-only GitHub MCP tools, ask for pull request creation, and deny merge/release tools.

## Verification

```bash
agentfence check --actor codex -- git status --short
agentfence simulate shell --actor codex -- pnpm install
agentfence audit report --format markdown --limit 100
```
