# MCP Governance

AgentFence treats MCP access as a policy decision problem:

```text
Agent -> AgentFence MCP Proxy -> Real MCP Server
```

The current code implements decision primitives and an initial stdio proxy.

## Current Command

```bash
agentfence mcp check --server github --kind tool --name merge_pull_request
```

Example response:

```json
{
  "request": {
    "server": "github",
    "kind": "tool",
    "name": "merge_pull_request",
    "arguments": null
  },
  "decision": {
    "decision": "deny",
    "reason": "matched MCP tool policy for github/merge_pull_request",
    "matchedRule": "mcp.servers.github.tools.merge_pull_request",
    "risk": "medium"
  }
}
```

## Stdio Proxy

Run an upstream MCP server behind AgentFence:

```bash
agentfence mcp proxy --server github -- node path/to/github-mcp-server.js
```

The proxy inspects client-to-server JSON-RPC messages:

- `tools/call` maps to MCP `tool` policy.
- `resources/read` maps to MCP `resource` policy.
- `prompts/get` maps to MCP `prompt` policy.
- `tools/list`, `resources/list`, and `prompts/list` responses are filtered to remove denied entries.

Allowed requests are forwarded to the upstream server. Denied requests receive a JSON-RPC error response and never reach upstream.

`ask` decisions default to deny in stdio proxy mode:

```bash
agentfence mcp proxy --server github --ask-mode deny -- node server.js
```

Use `--ask-mode allow` only for trusted local testing. Use `--ask-mode queue` to create a daemon approval request and wait for the desktop UI or CLI to resolve it:

```bash
agentfence mcp proxy --server github --ask-mode queue -- node server.js
```

## Remaining Proxy Work

The proxy should:

- Register upstream MCP servers.
- Redact sensitive outputs before audit logging.
- Support non-stdio transports.
