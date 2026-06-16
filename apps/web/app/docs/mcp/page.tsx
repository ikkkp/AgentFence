export default function McpPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence Docs</a>
      <h1>MCP Controls</h1>
      <p>
        MCP policy rules control which servers, tools, resources, and prompts an agent may access. AgentFence
        includes decision primitives and an initial stdio proxy for client-to-server calls.
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
    </main>
  );
}
