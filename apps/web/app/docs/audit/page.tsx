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
agentfence audit export --format csv --output audit.csv
agentfence audit report --format markdown --output audit-report.md`}</pre>
      <p>
        Reports summarize decisions, risks, actors, actions, and recent deny or ask events.
      </p>
      <h2>Daemon endpoint</h2>
      <p>
        The daemon can return recent rows for the desktop app or export them for compliance workflows.
      </p>
      <pre>{`curl "http://127.0.0.1:37421/audit?limit=50"
curl "http://127.0.0.1:37421/audit?limit=50&actor=codex&decision=deny&action=shell.exec"
curl "http://127.0.0.1:37421/audit/export?format=csv&limit=1000"`}</pre>
      <p>
        Query filters are exact matches for actor, decision, and action.
      </p>
    </main>
  );
}
