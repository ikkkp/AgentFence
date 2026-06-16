export default function McpPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence Docs</a>
      <h1>MCP Controls</h1>
      <p>
        MCP policy rules control which servers, tools, resources, and prompts an agent may access. AgentFence
        includes decision primitives, a stdio proxy, and a scoped HTTP JSON-RPC proxy for client-to-server calls.
      </p>
      <pre>{`agentfence mcp check \\
  --server github \\
  --kind tool \\
  --name create_pull_request`}</pre>
      <h2>Stdio proxy</h2>
      <pre>{`agentfence mcp proxy --server github -- node path/to/github-mcp-server.js`}</pre>
      <p>
        The proxy enforces tools/call, resources/read, and prompts/get, filters denied list entries,
        and can wait on the daemon approval queue with --ask-mode queue.
      </p>
      <h2>HTTP JSON-RPC proxy</h2>
      <pre>{`agentfence mcp http-proxy \\
  --server github \\
  --listen 127.0.0.1:37422 \\
  --upstream http://127.0.0.1:3000/mcp`}</pre>
      <p>
        The HTTP proxy applies the same checks to HTTP POST JSON-RPC bodies and passes through GET/SSE
        or chunked streaming responses after request-level checks.
      </p>
      <h2>Rate limits</h2>
      <p>
        Per-server rateLimit policy blocks excessive MCP calls inside the proxy before they reach the
        upstream server.
      </p>
      <pre>{`{
  "mcp": {
    "servers": {
      "github": {
        "rateLimit": {
          "enabled": true,
          "maxRequests": 30,
          "windowSeconds": 60
        }
      }
    }
  }
}`}</pre>
    </main>
  );
}
