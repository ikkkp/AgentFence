import {
  ArrowRight,
  BookOpen,
  FileJson,
  GitBranch,
  Network,
  PackageCheck,
  ShieldCheck,
  TerminalSquare,
  Workflow
} from "lucide-react";
import { sitePath } from "./site-path";

const primaryDocs = [
  {
    href: "/docs/quickstart",
    icon: <TerminalSquare />,
    title: "Quickstart",
    body: "Initialize a policy, run guarded commands, inspect approvals, and read audit logs."
  },
  {
    href: "/docs/architecture",
    icon: <Workflow />,
    title: "Architecture",
    body: "Understand the CLI, daemon, policy engine, audit store, desktop UI, and MCP proxy."
  },
  {
    href: "/docs/policy",
    icon: <FileJson />,
    title: "Policy JSON",
    body: "Review the deterministic policy model for shell, filesystem, network, MCP, skills, and bundles."
  },
  {
    href: "/docs/mcp",
    icon: <Network />,
    title: "MCP Governance",
    body: "Route stdio and HTTP MCP servers through AgentFence and filter tool/resource/prompt access."
  }
];

const projectDocs = [
  { href: "/docs/integrations", label: "Agent integrations" },
  { href: "/docs/audit", label: "Audit export" },
  { href: "/docs/development", label: "Development workflow" },
  { href: "/docs/release", label: "Release and packaging" },
  { href: "/security", label: "Security model" },
  { href: "/changelog", label: "Changelog" }
];

export default function HomePage() {
  return (
    <main>
      <header className="nav">
        <a className="logo" href={sitePath("/")}>
          <span>AF</span>
          AgentFence Docs
        </a>
        <nav>
          <a href={sitePath("/docs")}>Docs</a>
          <a href={sitePath("/docs/integrations")}>Integrations</a>
          <a href={sitePath("/security")}>Security</a>
          <a href={sitePath("/download")}>Download</a>
          <a className="button small" href="https://github.com/ikkkp/AgentFence">GitHub</a>
        </nav>
      </header>

      <section className="doc-hero">
        <div>
          <p className="eyebrow">Project Documentation</p>
          <h1>AgentFence</h1>
          <p className="lede">
            A local-first permission gateway for Claude Code, Codex, and MCP-based agents. These docs cover setup,
            policies, approvals, audit logs, MCP controls, integrations, packaging, and current security boundaries.
          </p>
          <div className="actions">
            <a className="button" href={sitePath("/docs/quickstart")}>
              Start with quickstart <ArrowRight size={18} />
            </a>
            <a className="button secondary" href={sitePath("/docs")}>
              Browse all docs <BookOpen size={18} />
            </a>
          </div>
        </div>
        <div className="terminal" aria-label="AgentFence documentation example">
          <div className="dots"><span /><span /><span /></div>
          <pre>{`agentfence init --preset developer
agentfence run --actor codex -- codex
agentfence mcp proxy --server github -- node server.js
agentfence audit report --format markdown`}</pre>
        </div>
      </section>

      <section className="doc-grid" aria-label="Primary documentation">
        {primaryDocs.map((doc) => (
          <a className="doc-card" href={sitePath(doc.href)} key={doc.title}>
            <div className="feature-icon">{doc.icon}</div>
            <h2>{doc.title}</h2>
            <p>{doc.body}</p>
          </a>
        ))}
      </section>

      <section className="band">
        <div>
          <p className="eyebrow">Project References</p>
          <h2>Everything needed to operate and extend AgentFence.</h2>
        </div>
        <ul>
          {projectDocs.map((doc) => (
            <li key={doc.href}>
              {doc.href.includes("release") ? <PackageCheck /> : doc.href.includes("changelog") ? <GitBranch /> : <ShieldCheck />}
              <a href={sitePath(doc.href)}>{doc.label}</a>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
