const releases = [
  {
    title: "Unreleased",
    date: "June 16, 2026",
    items: [
      "Added audit log filtering by actor, decision, and action in the daemon and desktop app.",
      "Added desktop policy diff previews before saving JSON policy edits.",
      "Added CLI integration profiles for Codex, Claude Code, Cursor-style agents, and generic MCP clients.",
      "Added MCP proxy rate limits and audit events for tool, resource, and prompt decisions.",
      "Added a side-effect-free shell policy simulator for CLI, daemon, and desktop workflows."
    ]
  },
  {
    title: "Initial implementation slice",
    date: "June 16, 2026",
    items: [
      "Created the Rust and pnpm monorepo with CLI, daemon, policy, audit, MCP, desktop, and website packages.",
      "Implemented guarded shell execution, policy discovery, SQLite audit logging, and approval requests.",
      "Implemented the first Tauri desktop control plane and public website documentation."
    ]
  }
];

export default function ChangelogPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence</a>
      <h1>Changelog</h1>
      <p>
        Product changes are tracked here as AgentFence moves from local shell governance toward a
        broader agent permission control plane.
      </p>
      <section className="entry-list">
        {releases.map((release) => (
          <article className="entry" key={release.title}>
            <p className="meta">{release.date}</p>
            <h2>{release.title}</h2>
            <ul>
              {release.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
        ))}
      </section>
    </main>
  );
}
