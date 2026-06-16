# AgentFence Roadmap

AgentFence is a local permission gateway for AI coding agents such as Claude Code, Codex, and custom MCP-based agents. Its goal is to make local agent actions inspectable, governable, auditable, and easy to approve without slowing down normal development.

## Product Direction

AgentFence should become the local control plane for AI agent execution:

- Control shell commands, filesystem access, MCP tools, skills, and external tool extensions.
- Provide deterministic policy enforcement backed by a JSON policy file.
- Offer human approval flows for high-risk actions.
- Keep a full local audit trail for commands, tool calls, and policy decisions.
- Provide a desktop UI for live approvals, policy editing, and audit review.
- Provide a web presence for downloads, documentation, positioning, and future commercial plans.

## Current Implementation Status

As of the first repository implementation slice, AgentFence has working foundations for:

- Milestone 0 foundation: Cargo workspace, pnpm workspace, policy schema, docs, CI, desktop app, and website.
- Milestone 1 shell permission MVP: `agentfence run`, line-oriented `agentfence shell`, command risk classification, allow/deny/ask decisions, CLI approval prompt, policy discovery, and SQLite audit logs.
- Milestone 2 desktop MVP: Tauri control plane with daemon health, live approvals, policy assistant preview, guided JSON Patch review, audit-driven policy suggestions, structured quick-rule editing, audit/export surfaces, MCP and skill controls.
- Milestone 3 MCP proxy: stdio and scoped HTTP JSON-RPC/SSE proxy enforcement for `tools/call`, `resources/read`, and `prompts/get`, plus list filtering for complete JSON, chunked JSON, and SSE responses, daemon-backed ask mode, rate limits, and audit events.
- Milestone 4 controls: filesystem, network, skill, MCP, MCP rate limits, secret redaction, policy presets, and guarded-command network domain checks.
- Milestone 5 policy assistant and simulator: deterministic JSON Patch proposal/apply flow with per-operation review, reusable rule packs, review presets, audit-driven narrower-rule suggestions after repeated approvals, plus side-effect-free shell simulation and explanations.
- Milestone 6 website/docs: homepage, download page, security page, changelog, blog foundation, quickstart, policy, MCP, and audit documentation.
- Milestone 7 integration docs: Codex, Claude Code, Cursor-style, and generic MCP wrapper profiles, per-agent setup guides, CLI wrapper installation, and optional PATH registration.
- Milestone 8 foundations: signed policy bundles, verification, import, organization policy templates, audit export, and local audit reports.

Remaining hardening work is concentrated around full PTY shell interception, OS-level filesystem controls, full network proxying, open-ended non-JSON MCP stream filtering, richer policy authoring workflows, and optional team/cloud features.

## Guiding Principles

- Local-first: core permissions, logs, and approvals work without a cloud dependency.
- Enforced, not prompted: the policy engine makes the decision, not the agent prompt.
- Explainable: every allow, deny, and ask decision should show the matching rule and reason.
- Composable: shell, MCP, skill, filesystem, and network controls share the same policy model.
- Safe by default: unknown high-impact actions should require approval.
- Agent-agnostic: Claude Code, Codex, Cursor-style agents, and custom agents should be supported through wrappers, proxies, or SDKs.

## Milestone 0: Foundation

Goal: establish the repo, product shape, and technical skeleton.

Scope:

- Define project architecture.
- Define `agentfence.policy.json` schema.
- Create CLI, daemon, policy engine, audit, desktop app, and website package layout.
- Add initial documentation.
- Add developer setup guide.
- Add basic CI for formatting, linting, and tests.

Recommended stack:

- Core: Rust
- CLI: Rust with `clap`
- Daemon API: local HTTP/WebSocket or JSON-RPC
- Audit store: SQLite
- Desktop: Tauri v2 + React + TypeScript + Vite
- Website: Next.js + TypeScript + Tailwind CSS + MDX
- Monorepo: pnpm + Turborepo for web packages, Cargo workspace for Rust crates

Exit criteria:

- Repository builds a placeholder CLI and desktop app.
- Policy schema exists and validates sample policies.
- CI runs on every pull request.

## Milestone 1: Shell Permission MVP

Goal: make AgentFence useful for real local agent command control.

Scope:

- Implement `agentfence run -- <command>`.
- Intercept shell commands launched through the AgentFence wrapper.
- Classify commands by risk.
- Apply allow, deny, and ask policy decisions.
- Add CLI approval prompt for ask decisions.
- Write audit events to SQLite.
- Support project-local policy discovery.

Core commands:

```bash
agentfence init
agentfence run -- codex
agentfence run -- claude
agentfence policy validate
agentfence logs
```

Initial policy decisions:

- `allow`
- `deny`
- `ask`
- `allow_once`
- `allow_for_session`

Exit criteria:

- Read-only commands can be auto-allowed.
- Dangerous delete commands can be denied.
- Package installs and write operations can require approval.
- All decisions are logged with actor, command, cwd, matched rule, and timestamp.

## Milestone 2: Desktop Client MVP

Goal: provide a polished local UI for approvals and audit visibility.

Scope:

- Tauri desktop shell.
- Dashboard for current agent sessions and recent events.
- Live approval queue.
- Audit log table with filters.
- Policy editor with JSON validation.
- Local daemon connection status.
- Desktop notifications for approval requests.

Key views:

- Dashboard
- Live Approvals
- Audit Log
- Policy Editor
- Settings

Exit criteria:

- User can approve or deny shell actions from the desktop app.
- User can inspect recent command history.
- User can edit and validate policy JSON.
- Desktop app works on Windows first, with macOS and Linux as follow-up targets.

## Milestone 3: MCP Proxy

Goal: control agent access to MCP servers, tools, resources, and prompts.

Scope:

- Implement AgentFence MCP proxy.
- Register upstream MCP servers.
- Filter tools/resources/prompts by policy.
- Apply allow, deny, and ask decisions per MCP tool call.
- Inspect MCP arguments before forwarding.
- Log MCP call metadata and decision results.
- Support per-server and per-tool rules.

Example controls:

- Allow GitHub read operations.
- Ask before creating pull requests.
- Deny merge, deploy, secret, or credential-related tools.
- Limit filesystem MCP roots.

Exit criteria:

- An agent can connect to AgentFence as its MCP endpoint.
- AgentFence forwards allowed tool calls to real MCP servers.
- Denied MCP calls never reach the upstream server.
- Ask decisions can be approved from CLI or desktop UI.

## Milestone 4: Filesystem, Network, and Secret Controls

Goal: expand from command/tool control into practical local safety boundaries.

Scope:

- Enforce allow and deny filesystem roots.
- Flag sensitive files such as `.env`, SSH keys, cloud credentials, and token stores.
- Add network domain policy for commands and tools where controllable.
- Add secret detection and redaction in audit logs.
- Add rate limits for external tool calls.
- Add policy presets for common risk profiles.

Policy presets:

- `read-only`
- `developer`
- `strict`
- `trusted-project`
- `ci-like`

Exit criteria:

- Access to configured sensitive paths is denied or requires approval.
- Audit logs avoid storing raw secrets.
- Policy presets can be selected during `agentfence init`.

## Milestone 5: LLM Policy Assistant

Goal: let users manage permissions conversationally while keeping deterministic enforcement.

Scope:

- Natural-language policy editing.
- Generate JSON Patch proposals instead of direct writes.
- Show policy diffs before applying changes.
- Explain why a command was blocked.
- Suggest narrower rules after repeated approvals.
- Add a policy simulator for testing hypothetical actions.

Example prompts:

```text
Allow Codex to run tests in this repo, but ask before installing dependencies.
Deny all production deploy commands.
Explain why this MCP call was blocked.
Make this policy stricter for unknown network requests.
```

Exit criteria:

- LLM assistant never directly bypasses policy enforcement.
- All generated policy changes require explicit user confirmation.
- Policy assistant can explain matched rules and suggest safer alternatives.

## Milestone 6: Website and Documentation

Goal: create the public presence needed for adoption.

Scope:

- Marketing homepage.
- Download page.
- Documentation site.
- Quickstart guide.
- Policy reference.
- MCP proxy guide.
- Security model page.
- Changelog.
- Blog foundation.

Recommended pages:

- `/`
- `/download`
- `/docs`
- `/docs/quickstart`
- `/docs/policy`
- `/docs/mcp`
- `/security`
- `/changelog`

Exit criteria:

- New users can understand the product in under one minute.
- Developers can install and run the shell MVP from the docs.
- Security page clearly explains local-first enforcement and current limitations.

## Milestone 7: Agent Integrations

Goal: improve support for common local coding agents.

Scope:

- Codex integration guide and wrapper profile.
- Claude Code integration guide and wrapper profile.
- Cursor-style agent integration notes.
- Generic MCP client integration guide.
- Per-agent defaults for policy presets.
- Compatibility matrix.

Exit criteria:

- Users can start major local agents through AgentFence with documented commands.
- Integration docs include known limitations and recommended policies.

## Milestone 8: Team and Pro Features

Goal: prepare a commercial path without weakening the local-first foundation.

Scope:

- Signed policy bundles.
- Organization policy templates.
- Team audit export.
- Optional cloud sync.
- Central policy distribution.
- SSO for team administration.
- Compliance reports.
- Remote approval workflows.

Exit criteria:

- Local open-source version remains useful on its own.
- Pro/team features add collaboration, governance, and reporting rather than basic safety.

## Suggested Timeline

The exact timeline depends on team size, but a realistic solo or small-team plan is:

- Weeks 1-2: foundation, repo structure, policy schema, placeholder CLI.
- Weeks 3-5: shell permission MVP and audit logging.
- Weeks 6-8: desktop client MVP.
- Weeks 9-12: MCP proxy and MCP policy controls.
- Weeks 13-15: filesystem, network, secret controls.
- Weeks 16-18: LLM policy assistant.
- Weeks 19-20: public website and documentation.
- Weeks 21+: integrations, hardening, packaging, and team features.

## Near-Term Backlog

- Keep CLI, daemon, desktop, and website verification green in CI.
- Add release installer packaging around the wrapper PATH registration flow.
- Add trust policy for accepted review preset signing keys.
- Explore deeper filtering for open-ended non-JSON MCP streams.
- Explore full PTY integration for agents that launch nested commands.
- Explore OS-level or proxy-level network and filesystem controls.

## Open Design Questions

- How should the current wrapper plus line-oriented shell evolve into full PTY interception?
- Should the policy engine use a custom matcher first, or adopt OPA/Rego later?
- How much network control is feasible without requiring a full proxy/VPN layer?
- Which MCP transports should be prioritized first: stdio, HTTP, or both?
- How should temporary session grants be scoped: actor, cwd, command pattern, or all three?
- How should AgentFence represent skill access for agents that do not expose skills as first-class APIs?

## First Public Release Target

Version: `v0.1.0`

Release theme:

```text
Local shell permissions and audit logs for AI coding agents.
```

Must include:

- `agentfence init`
- `agentfence run -- <agent>`
- JSON policy validation
- Shell command allow/deny/ask
- CLI approvals
- SQLite audit logs
- Basic documentation

Should include:

- Desktop approval queue
- Audit log UI
- Example policies
- MCP stdio proxy
- Network domain checks for guarded shell commands
- Deterministic policy assistant
- Signed policy bundles

Can wait:

- Team sync
- Advanced network controls
