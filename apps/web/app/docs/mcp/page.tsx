import { sitePath } from "../../site-path";

export default function McpPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/")}>AgentFence Docs</a>
      <h1>MCP Controls</h1>
      <p>
        MCP policy rules control which servers, tools, resources, and prompts an agent may access. AgentFence
        includes decision primitives, a stdio proxy, and a scoped HTTP JSON-RPC proxy for client-to-server calls.
      </p>
      <pre>{`agentfence mcp check \\
  --server github \\
  --kind tool \\
  --name create_pull_request

agentfence mcp check \\
  --server github \\
  --kind tool \\
  --name list_issues \\
  --arguments-json '{"api_key":"sk-test"}'`}</pre>
      <p>
        MCP arguments are inspected before forwarding. Secret-looking keys or values, sensitive paths,
        production or release context, and high-impact tool names are written to `argumentInspection`;
        high or critical findings upgrade otherwise allowed calls to ask.
      </p>
      <pre>{`# Windows-friendly argument simulation
Set-Content -Encoding UTF8 .\\mcp-arguments.json '{"api_key":"sk-test"}'
agentfence mcp check --server github --kind tool --name list_issues --arguments-file .\\mcp-arguments.json`}</pre>
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
        The HTTP proxy applies the same checks to HTTP POST JSON-RPC bodies, filters denied list entries
        from complete JSON, chunked JSON, and SSE list responses, and passes other streaming responses through after
        request-level checks.
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
