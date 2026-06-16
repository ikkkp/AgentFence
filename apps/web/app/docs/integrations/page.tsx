export default function IntegrationsPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence Docs</a>
      <h1>Agent Integrations</h1>
      <p>
        Launch local coding agents through AgentFence wrappers, or place the MCP proxy between an
        agent and its upstream MCP servers.
      </p>
      <h2>Built-in profiles</h2>
      <pre>{`agentfence integrations list
agentfence integrations show codex --format shell
agentfence integrations show claude-code --format powershell
agentfence integrations show generic-mcp --format json
agentfence integrations install codex --format powershell --output-dir .agentfence/wrappers --force --add-to-path`}</pre>
      <p>
        `--add-to-path` persists the wrapper directory on your user PATH so a new terminal can run
        the generated wrapper by name.
      </p>
      <h2>Codex</h2>
      <pre>{`agentfence init --preset developer --project codex-project
agentfence run --actor codex -- codex`}</pre>
      <p>
        Use `examples/codex.policy.json` and `examples/integrations/codex-wrapper.json` as a starting point.
      </p>
      <p><a href="/docs/integrations/codex">Open Codex guide</a></p>
      <h2>Claude Code</h2>
      <pre>{`agentfence init --preset developer --project claude-code-project
agentfence run --actor claude-code -- claude`}</pre>
      <p>
        Use `examples/claude-code.policy.json` and `examples/integrations/claude-code-wrapper.json`.
      </p>
      <p><a href="/docs/integrations/claude-code">Open Claude Code guide</a></p>
      <h2>Cursor-style agents</h2>
      <pre>{`agentfence run --actor cursor-agent -- node ./agent-entrypoint.js`}</pre>
      <p>
        Wrap the underlying command or harness that launches local actions, then loosen policy from
        audit evidence.
      </p>
      <p><a href="/docs/integrations/cursor-style">Open Cursor-style guide</a></p>
      <h2>Generic MCP clients</h2>
      <pre>{`agentfence mcp proxy \\
  --server github \\
  --ask-mode queue \\
  -- node path/to/github-mcp-server.js

agentfence mcp http-proxy \\
  --server github \\
  --upstream http://127.0.0.1:3000/mcp`}</pre>
      <p>
        `--ask-mode queue` sends ask decisions to the daemon so the desktop approval queue can resolve them.
      </p>
      <p><a href="/docs/integrations/generic-mcp">Open Generic MCP guide</a></p>
    </main>
  );
}
