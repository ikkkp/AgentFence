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
agentfence mcp proxy --server github --audit .agentfence/audit.sqlite -- node path/to/server.js
```

The proxy inspects client-to-server JSON-RPC messages:

- `tools/call` maps to MCP `tool` policy.
- `resources/read` maps to MCP `resource` policy.
- `prompts/get` maps to MCP `prompt` policy.
- `tools/list`, `resources/list`, and `prompts/list` responses are filtered to remove denied entries.
- `rateLimit` blocks excessive allowed calls before they reach the upstream server.

Allowed requests are forwarded to the upstream server. Denied requests receive a JSON-RPC error response and never reach upstream.

Each inspected call writes an audit event when policy audit logging is enabled. The event subject is `server/name`, the action is `mcp.tool`, `mcp.resource`, or `mcp.prompt`, and metadata includes the MCP arguments.

`ask` decisions default to deny in stdio proxy mode:

```bash
agentfence mcp proxy --server github --ask-mode deny -- node server.js
```

Use `--ask-mode allow` only for trusted local testing. Use `--ask-mode queue` to create a daemon approval request and wait for the desktop UI or CLI to resolve it:

```bash
agentfence mcp proxy --server github --ask-mode queue -- node server.js
```

## Rate Limits

Rate limits are configured per MCP server and enforced inside the stdio proxy process:

```json
{
  "mcp": {
    "servers": {
      "github": {
        "enabled": true,
        "decision": "ask",
        "rateLimit": {
          "enabled": true,
          "maxRequests": 30,
          "windowSeconds": 60
        }
      }
    }
  }
}
```

When the limit is exceeded, the proxy returns an MCP error response and does not forward the call to the upstream server.

## Remaining Proxy Work

The proxy should:

- Register upstream MCP servers.
- Redact sensitive outputs before audit logging.
- Support non-stdio transports.
