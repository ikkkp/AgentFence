# Agent Integrations

AgentFence works best when the agent process is launched through a wrapper command or when the agent's MCP servers are routed through `agentfence mcp proxy`.

## Wrapper Pattern

Use `agentfence run` as the outer command:

```bash
agentfence run --actor codex -- codex
agentfence run --actor claude-code -- claude
```

The `--actor` value selects the actor recorded in audit logs and can be matched by policy.

## Codex

Recommended profile:

- Preset: `developer`
- Actor: `codex`
- Shell: allow read-only inspection and local tests, ask for dependency installs, deny broad destructive commands.
- Network: allow package registries and GitHub, ask for unknown domains.
- MCP: allow read-only GitHub operations, ask for writes, deny merge/deploy style tools.

```bash
agentfence init --preset developer --project codex-project
agentfence run --actor codex -- codex
```

Example policy: `examples/codex.policy.json`
Wrapper profile: `examples/integrations/codex-wrapper.json`

## Claude Code

Recommended profile:

- Preset: `developer`
- Actor: `claude-code`
- Shell: ask for repository-changing commands such as commit, reset, and clean.
- Filesystem: deny credential directories and ask for writes.
- MCP: allow filesystem reads, ask for writes, deny deletes.

```bash
agentfence init --preset developer --project claude-code-project
agentfence run --actor claude-code -- claude
```

Example policy: `examples/claude-code.policy.json`
Wrapper profile: `examples/integrations/claude-code-wrapper.json`

## Cursor-Style Agents

For agents that do not expose a stable CLI entrypoint, run their underlying command, script, or local automation harness through AgentFence:

```bash
agentfence run --actor cursor-agent -- node ./agent-entrypoint.js
```

Recommended profile:

- Preset: `strict` for unknown agent harnesses.
- Actor: `cursor-agent`
- Shell: allow inspection commands only until the workflow is known.
- MCP: register only the specific upstream servers needed for the project.

Wrapper profile: `examples/integrations/cursor-style-wrapper.json`

## Generic MCP Client

Place the AgentFence proxy between the client and upstream server:

```bash
agentfence mcp proxy --server github --ask-mode queue -- node path/to/github-mcp-server.js
```

The stdio proxy enforces:

- `tools/call`
- `resources/read`
- `prompts/get`
- `tools/list`, `resources/list`, and `prompts/list` filtering

Wrapper profile: `examples/integrations/generic-mcp-proxy.json`

## Compatibility Matrix

| Integration | Shell wrapper | MCP stdio proxy | Desktop approvals | Notes |
| --- | --- | --- | --- | --- |
| Codex | Supported | Supported when configured as an MCP client | Supported | Start Codex through `agentfence run` for shell enforcement. |
| Claude Code | Supported | Supported when configured as an MCP client | Supported | Use actor `claude-code` for policy and audit separation. |
| Cursor-style agents | Harness dependent | Supported for MCP servers | Supported | Wrap the underlying command or SDK runner. |
| Generic MCP clients | Not applicable | Supported | Supported with `--ask-mode queue` | HTTP/SSE MCP transports are future work. |

## Known Limits

- Wrapper-only shell control cannot intercept commands an agent launches outside AgentFence.
- OS-level filesystem and network enforcement are not yet implemented.
- MCP proxy coverage currently focuses on stdio transport.
