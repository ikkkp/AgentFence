export default function ClaudeCodeIntegrationPage() {
  return (
    <main className="page">
      <a className="back" href="/docs/integrations">Integrations</a>
      <h1>Claude Code Integration</h1>
      <p>
        Use the `claude-code` actor to keep Claude Code approvals and audit history separate from other local agents.
      </p>
      <pre>{`agentfence init --preset developer --project claude-code-project
agentfence run --actor claude-code -- claude`}</pre>
      <h2>Profile</h2>
      <pre>{`agentfence integrations show claude-code --format powershell
agentfence integrations install claude-code --format powershell --output-dir .agentfence/wrappers --force --add-to-path`}</pre>
      <h2>Filesystem MCP</h2>
      <pre>{`{
  "mcp": {
    "servers": {
      "filesystem": {
        "tools": {
          "read_file": "allow",
          "write_file": "ask",
          "delete_file": "deny"
        }
      }
    }
  }
}`}</pre>
      <h2>Checks</h2>
      <pre>{`agentfence check --actor claude-code -- git status
agentfence filesystem check --operation read --path ~/.ssh/id_rsa
agentfence policy suggest --threshold 3 --limit 1000`}</pre>
    </main>
  );
}
