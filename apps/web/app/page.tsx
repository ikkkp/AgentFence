import { ArrowRight, CheckCircle2, FileJson, LockKeyhole, TerminalSquare } from "lucide-react";
import { sitePath } from "./site-path";

const features = [
  {
    icon: <TerminalSquare />,
    title: "Shell governance",
    body: "Classify, allow, deny, or approve commands before local agents run them."
  },
  {
    icon: <FileJson />,
    title: "JSON policy",
    body: "Use deterministic policies that are reviewable, versionable, and explainable."
  },
  {
    icon: <LockKeyhole />,
    title: "MCP and skill gates",
    body: "Proxy external tools and limit agent access to sensitive capabilities."
  }
];

export default function HomePage() {
  return (
    <main>
      <header className="nav">
        <a className="logo" href={sitePath("/")}>
          <span>AF</span>
          AgentFence
        </a>
        <nav>
          <a href={sitePath("/docs/quickstart")}>Docs</a>
          <a href={sitePath("/docs/integrations")}>Integrations</a>
          <a href={sitePath("/security")}>Security</a>
          <a href={sitePath("/changelog")}>Changelog</a>
          <a href={sitePath("/blog")}>Blog</a>
          <a href={sitePath("/download")}>Download</a>
          <a className="button small" href="https://github.com/ikkkp/AgentFence">GitHub</a>
        </nav>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">Local AI Agent Permission Gateway</p>
          <h1>AgentFence</h1>
          <p className="lede">
            Give Claude Code, Codex, and custom MCP agents a local permission boundary for shell commands,
            MCP tools, skills, files, and external extensions.
          </p>
          <div className="actions">
            <a className="button" href={sitePath("/docs/quickstart")}>
              Start building <ArrowRight size={18} />
            </a>
            <a className="button secondary" href={sitePath("/download")}>Download desktop</a>
          </div>
        </div>
        <div className="terminal" aria-label="AgentFence CLI example">
          <div className="dots"><span /><span /><span /></div>
          <pre>{`$ agentfence run -- codex
decision: ask
risk: high
reason: package installation can modify the environment

allow once? [y/N]`}</pre>
        </div>
      </section>

      <section className="features">
        {features.map((feature) => (
          <article key={feature.title}>
            <div className="feature-icon">{feature.icon}</div>
            <h2>{feature.title}</h2>
            <p>{feature.body}</p>
          </article>
        ))}
      </section>

      <section className="band">
        <div>
          <p className="eyebrow">Roadmap</p>
          <h2>From shell approvals to a full local control plane.</h2>
        </div>
        <ul>
          <li><CheckCircle2 /> Shell permission MVP and audit logs</li>
          <li><CheckCircle2 /> Desktop approval queue and policy editor</li>
          <li><CheckCircle2 /> MCP proxy, skill gates, and LLM policy assistant</li>
          <li><CheckCircle2 /> Codex, Claude Code, and generic MCP integration guides</li>
          <li><CheckCircle2 /> Public changelog and blog foundation</li>
        </ul>
      </section>
    </main>
  );
}
