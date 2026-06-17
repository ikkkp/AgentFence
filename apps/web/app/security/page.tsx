import { sitePath } from "../site-path";

export default function SecurityPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/")}>AgentFence</a>
      <h1>Security Model</h1>
      <p>
        AgentFence is local-first. Policy evaluation, approval decisions, and audit logging happen on
        the user machine. The agent prompt is not trusted as an enforcement layer.
      </p>
      <h2>Current guarantees</h2>
      <ul>
        <li>Shell commands launched through `agentfence run`, entered in `agentfence shell`, or submitted through `agentfence shell --pty` are checked before execution.</li>
        <li>URL-like and common Git/SSH remotes in guarded commands are checked against network policy.</li>
        <li>MCP stdio, HTTP JSON-RPC, batch JSON-RPC, and GET/SSE stream requests can be routed through AgentFence proxies.</li>
        <li>Audit logs are stored locally in SQLite.</li>
        <li>Release and dependency workflows include RustSec advisory checks, critical npm advisory checks, checksums, and Dependabot update coverage.</li>
      </ul>
      <h2>Known limits</h2>
      <ul>
        <li>Shell control cannot intercept commands an agent launches outside AgentFence; the PTY mode is an MVP that checks submitted command lines, not raw key events.</li>
        <li>Full network enforcement still requires a proxy or OS-level integration in a later milestone.</li>
        <li>Stream-aware filtering is limited; list filtering applies to complete JSON, chunked JSON, batch JSON-RPC, and SSE list responses.</li>
      </ul>
    </main>
  );
}
