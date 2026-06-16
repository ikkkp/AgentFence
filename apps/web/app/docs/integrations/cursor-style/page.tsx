export default function CursorStyleIntegrationPage() {
  return (
    <main className="page">
      <a className="back" href="/docs/integrations">Integrations</a>
      <h1>Cursor-Style Agents</h1>
      <p>
        Wrap the executable, script, or harness that actually launches local commands.
      </p>
      <pre>{`agentfence init --preset strict --project cursor-style-project
agentfence run --actor cursor-agent -- node ./agent-entrypoint.js`}</pre>
      <h2>Profile</h2>
      <pre>{`agentfence integrations show cursor-style --format shell`}</pre>
      <h2>Checks</h2>
      <pre>{`agentfence check --actor cursor-agent -- git diff
agentfence audit report --format markdown --limit 100`}</pre>
      <p>
        For IDE flows that launch commands outside AgentFence, route MCP servers through the proxy and keep high-risk automation in explicit scripts.
      </p>
    </main>
  );
}
