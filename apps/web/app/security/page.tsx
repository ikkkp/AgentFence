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
        <li>Shell commands launched through `agentfence run` are checked before execution.</li>
        <li>URL-like and common Git/SSH remotes in guarded commands are checked against network policy.</li>
        <li>MCP stdio and non-streaming HTTP JSON-RPC calls can be enforced through AgentFence proxies.</li>
        <li>Audit logs are stored locally in SQLite.</li>
      </ul>
      <h2>Known limits</h2>
      <ul>
        <li>Wrapper-only shell control cannot intercept commands an agent launches outside AgentFence.</li>
        <li>Full network enforcement still requires a proxy or OS-level integration in a later milestone.</li>
        <li>MCP SSE and streaming HTTP responses remain future transport work.</li>
      </ul>
    </main>
  );
}
