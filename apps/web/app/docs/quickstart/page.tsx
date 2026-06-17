import { sitePath } from "../../site-path";

export default function QuickstartPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/")}>AgentFence Docs</a>
      <h1>Quickstart</h1>
      <ol>
        <li>Initialize a policy in your project.</li>
        <li>Run commands or agents through AgentFence.</li>
        <li>Review decisions and audit logs.</li>
      </ol>
      <pre>{`agentfence init
agentfence daemon start --listen 127.0.0.1:37421
agentfence daemon status
agentfence check -- git status
agentfence run -- git status --short
agentfence approvals list
agentfence logs`}</pre>
      <h2>Use a guarded shell</h2>
      <pre>{`agentfence shell --actor codex
agentfence> git status --short
agentfence> npm install
agentfence> exit

agentfence shell --pty --actor codex`}</pre>
      <p>
        The guarded shell checks each entered command before execution. The PTY mode starts a real
        pseudo-terminal child shell and checks submitted command lines before forwarding them.
      </p>
      <h2>Start an agent</h2>
      <pre>{`agentfence run --actor codex -- codex
agentfence run --actor claude-code -- claude`}</pre>
      <p>
        See the integrations guide for Codex, Claude Code, Cursor-style agents, and generic MCP clients.
      </p>
      <p>
        <a href={sitePath("/docs/integrations")}>Open integrations guide</a>
      </p>
    </main>
  );
}
