import { sitePath } from "../../site-path";

export default function ArchitecturePage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/docs")}>Project Documentation</a>
      <h1>Architecture</h1>
      <p>
        AgentFence is organized as a local control plane. Agents connect through wrappers, proxies, or
        SDK-style integrations, and policy decisions are deterministic, auditable, and local-first.
      </p>
      <pre>{`Agent
  Claude Code / Codex / Custom MCP Agent
        |
        v
AgentFence CLI / MCP Proxy / SDK
        |
        v
AgentFence Daemon
        |
        +-- Policy Engine
        +-- Shell Classifier
        +-- MCP Decision Layer
        +-- Audit Store
        +-- Desktop UI`}</pre>
      <h2>Components</h2>
      <ul>
        <li>`crates/agentfence-policy`: policy model, decisions, schema, policy bundles, suggestions, and simulation helpers.</li>
        <li>`crates/agentfence-cli`: daemon lifecycle controls, shell checks, guarded execution, MCP proxies, integration profiles, bundles, audits, and approvals.</li>
        <li>`crates/agentfence-daemon`: local HTTP API for health, shutdown, policy, approvals, audit, filesystem, network, skill, MCP, and simulation checks.</li>
        <li>`crates/agentfence-audit`: local SQLite audit persistence with secret redaction.</li>
        <li>`apps/desktop`: Tauri control plane for approvals, policy editing, audit review, MCP, skills, and settings.</li>
        <li>`apps/web`: this static project documentation site.</li>
      </ul>
      <h2>Current enforcement boundary</h2>
      <p>
        Shell enforcement applies when commands are launched through `agentfence run` or typed into
        `agentfence shell`. MCP enforcement applies when clients route stdio or HTTP MCP servers through
        AgentFence proxies. Full PTY interception, full network proxying, and OS-level filesystem controls
        remain hardening milestones.
      </p>
      <p>
        The local daemon can be managed with `agentfence daemon start`, `agentfence daemon status`,
        `agentfence daemon stop`, and `agentfence daemon restart`; the desktop app exposes the same default
        local start and stop flow.
      </p>
      <p>
        Wrapper-mode shell control is conservative around nested interpreters and high-impact tooling:
        `bash -lc`, `cmd /c`, `powershell -Command`, encoded PowerShell, package publishes, repository
        rewrites, and infrastructure apply or destroy commands are elevated before policy rules match.
      </p>
    </main>
  );
}
