const posts = [
  {
    title: "Why AgentFence Starts Local",
    date: "June 16, 2026",
    summary:
      "AI coding agents need real execution boundaries. AgentFence begins with local policy, approvals, and audit logs before adding optional team workflows."
  },
  {
    title: "Designing Permission Profiles for Codex and Claude Code",
    date: "June 16, 2026",
    summary:
      "Wrapper profiles make agent launches repeatable: the actor name, recommended preset, audit store, and MCP proxy command all become explicit."
  }
];

export default function BlogPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence</a>
      <h1>Blog</h1>
      <p>
        Notes on local-first AI agent security, permission UX, MCP governance, and the engineering
        tradeoffs behind AgentFence.
      </p>
      <section className="entry-list">
        {posts.map((post) => (
          <article className="entry" key={post.title}>
            <p className="meta">{post.date}</p>
            <h2>{post.title}</h2>
            <p>{post.summary}</p>
          </article>
        ))}
      </section>
    </main>
  );
}
