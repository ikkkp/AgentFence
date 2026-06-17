import { sitePath } from "../../../site-path";

export default function GenericMcpIntegrationPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/docs/integrations")}>Integrations</a>
      <h1>Generic MCP Clients</h1>
      <p>
        Put AgentFence between the MCP client and upstream server to enforce tools, resources, prompts, approvals, and audit.
      </p>
      <pre>{`agentfence integrations install generic-mcp --format shell --output-dir .agentfence/wrappers --force --add-to-path`}</pre>
      <h2>Stdio</h2>
      <pre>{`agentfence mcp proxy \\
  --server github \\
  --ask-mode queue \\
  -- node path/to/github-mcp-server.js`}</pre>
      <h2>HTTP</h2>
      <pre>{`agentfence mcp http-proxy \\
  --server github \\
  --listen 127.0.0.1:37422 \\
  --upstream http://127.0.0.1:3000/mcp`}</pre>
      <p>
        The HTTP proxy enforces single and batch JSON-RPC bodies, rejects denied batches without
        partial forwarding, and filters denied list entries from complete JSON, chunked JSON, batch,
        and SSE responses.
      </p>
      <h2>Checks</h2>
      <pre>{`agentfence mcp check --server github --kind tool --name create_pull_request
agentfence approvals list
agentfence audit report --format json --limit 100`}</pre>
    </main>
  );
}
