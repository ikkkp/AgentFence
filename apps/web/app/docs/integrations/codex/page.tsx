import { sitePath } from "../../../site-path";

export default function CodexIntegrationPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/docs/integrations")}>Integrations</a>
      <h1>Codex Integration</h1>
      <p>
        Run Codex with actor-specific audit rows, shell checks, network-domain checks, and optional MCP proxy enforcement.
      </p>
      <pre>{`agentfence init --preset developer --project codex-project
agentfence run --actor codex -- codex`}</pre>
      <h2>Profile</h2>
      <pre>{`agentfence integrations show codex --format shell
agentfence integrations install codex --format shell --output-dir .agentfence/wrappers --force --add-to-path`}</pre>
      <h2>MCP</h2>
      <pre>{`agentfence mcp proxy \\
  --server github \\
  --ask-mode queue \\
  -- node path/to/github-mcp-server.js`}</pre>
      <h2>Checks</h2>
      <pre>{`agentfence check --actor codex -- git status --short
agentfence simulate shell --actor codex -- pnpm install
agentfence audit report --format markdown --limit 100`}</pre>
    </main>
  );
}
