import { sitePath } from "../site-path";

const sections = [
  {
    title: "Start",
    links: [
      ["Quickstart", "/docs/quickstart"],
      ["Agent integrations", "/docs/integrations"],
      ["Download", "/download"]
    ]
  },
  {
    title: "Core system",
    links: [
      ["Architecture", "/docs/architecture"],
      ["Policy JSON", "/docs/policy"],
      ["MCP governance", "/docs/mcp"],
      ["Audit export", "/docs/audit"],
      ["Security model", "/security"]
    ]
  },
  {
    title: "Project operations",
    links: [
      ["Development workflow", "/docs/development"],
      ["Release and packaging", "/docs/release"],
      ["Changelog", "/changelog"],
      ["GitHub repository", "https://github.com/ikkkp/AgentFence"]
    ]
  }
];

export default function DocsIndexPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/")}>AgentFence Docs</a>
      <h1>Project Documentation</h1>
      <p>
        AgentFence is a local control plane for AI coding agents. This documentation covers the current
        implementation, operational workflows, policy model, and integration surfaces.
      </p>
      <section className="entry-list">
        {sections.map((section) => (
          <article className="entry" key={section.title}>
            <h2>{section.title}</h2>
            <ul className="doc-list">
              {section.links.map(([label, href]) => (
                <li key={href}>
                  <a href={href.startsWith("http") ? href : sitePath(href)}>{label}</a>
                </li>
              ))}
            </ul>
          </article>
        ))}
      </section>
    </main>
  );
}
