export default function SecurityPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence</a>
      <h1>Security Model</h1>
      <p>
        AgentFence is local-first. Policy evaluation, approval decisions, and audit logging happen on
        the user machine. The agent prompt is not trusted as an enforcement layer.
      </p>
      <h2>Current guarantees</h2>
      <ul>
        <li>Shell commands launched through `agentfence run` or entered in `agentfence shell` are checked before execution.</li>
        <li>URL-like and common Git/SSH remotes in guarded commands are checked against network policy.</li>
        <li>MCP stdio, HTTP JSON-RPC, and GET/SSE stream requests can be routed through AgentFence proxies.</li>
        <li>Audit logs are stored locally in SQLite.</li>
      </ul>
      <h2>Known limits</h2>
      <ul>
        <li>Shell control cannot intercept commands an agent launches outside AgentFence or a future full PTY integration.</li>
        <li>Full network enforcement still requires a proxy or OS-level integration in a later milestone.</li>
        <li>Stream-aware filtering is limited; list filtering applies to complete JSON and SSE list responses.</li>
      </ul>
    </main>
  );
}
