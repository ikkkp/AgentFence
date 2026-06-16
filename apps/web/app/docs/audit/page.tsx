export default function AuditPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence Docs</a>
      <h1>Audit Export</h1>
      <p>
        AgentFence stores audit events locally in SQLite and exports recent events as JSON or CSV.
      </p>
      <p>
        Guarded shell commands and MCP proxy decisions are recorded when audit logging is enabled.
      </p>
      <pre>{`agentfence audit export --format json --output audit.json
agentfence audit export --format csv --output audit.csv`}</pre>
      <h2>Daemon endpoint</h2>
      <pre>{`curl "http://127.0.0.1:37421/audit/export?format=csv&limit=1000"`}</pre>
    </main>
  );
}
