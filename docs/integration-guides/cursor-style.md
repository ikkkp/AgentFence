# Cursor-Style Agent Integration Guide

Cursor-style and IDE-embedded agents may not expose a stable top-level CLI. AgentFence can still guard the command, script, or harness that launches local actions.

## Initialize

Start strict for unknown harnesses:

```bash
agentfence init --preset strict --project cursor-style-project
```

## Launch The Harness

Wrap the executable that actually performs local work:

```bash
agentfence run --actor cursor-agent -- node ./agent-entrypoint.js
```

Equivalent built-in profile:

```bash
agentfence integrations show cursor-style --format shell
```

## Recommended Guardrails

- Start with inspection-only shell access.
- Allow only the MCP servers required by the project.
- Keep unknown network domains at `ask` or `deny`.
- Use audit reports and policy suggestions to loosen exact commands after observation.

## When The IDE Launches Commands Internally

Wrapper-only control cannot intercept work started outside AgentFence. For that setup, route MCP servers through AgentFence and keep high-risk shell automation in explicit scripts that can be launched through `agentfence run`.

## Verification

```bash
agentfence check --actor cursor-agent -- git diff
agentfence audit report --format markdown --limit 100
```
