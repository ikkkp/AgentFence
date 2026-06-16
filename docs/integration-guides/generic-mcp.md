# Generic MCP Client Integration Guide

Use AgentFence as a policy-enforcing MCP proxy when an agent supports custom MCP server commands or HTTP MCP endpoints.

Generate a reusable wrapper script when the client accepts a command path:

```bash
agentfence integrations install generic-mcp --format shell --output-dir .agentfence/wrappers --force --add-to-path
```

## Stdio MCP

```bash
agentfence mcp proxy \
  --server github \
  --ask-mode queue \
  -- node path/to/github-mcp-server.js
```

`--ask-mode queue` sends ask decisions to `agentfenced`, so the desktop UI or CLI can resolve them.

## HTTP MCP

```bash
agentfence mcp http-proxy \
  --server github \
  --listen 127.0.0.1:37422 \
  --upstream http://127.0.0.1:3000/mcp
```

Point the MCP client at `http://127.0.0.1:37422`. The proxy enforces POST JSON-RPC calls, filters denied entries from complete JSON, chunked JSON, and SSE list responses, and passes other streaming responses through after request-level checks.

## Policy Shape

```json
{
  "mcp": {
    "servers": {
      "github": {
        "enabled": true,
        "decision": "ask",
        "tools": {
          "list_pull_requests": "allow",
          "create_pull_request": "ask",
          "merge_pull_request": "deny"
        }
      }
    }
  }
}
```

## Verification

```bash
agentfence mcp check --server github --kind tool --name create_pull_request
agentfence approvals list
agentfence audit report --format json --limit 100
```
