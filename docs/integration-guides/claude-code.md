# Claude Code Integration Guide

Use the `claude-code` actor when launching Claude Code through AgentFence. This keeps Claude-specific audit history and approvals separate from Codex or other local agents.

## Initialize

```bash
agentfence init --preset developer --project claude-code-project
agentfence policy validate agentfence.policy.json
```

The example policy is `examples/claude-code.policy.json`.

## Launch Claude Code

```bash
agentfence run --actor claude-code -- claude
```

If the installed binary has a different name, replace the final command while keeping the actor:

```bash
agentfence run --actor claude-code -- claude-code
```

Equivalent built-in profile:

```bash
agentfence integrations show claude-code --format powershell
agentfence integrations install claude-code --format powershell --output-dir .agentfence/wrappers --force --add-to-path
```

## MCP Servers

For filesystem-oriented MCP servers, prefer explicit read/write rules:

```json
{
  "mcp": {
    "servers": {
      "filesystem": {
        "enabled": true,
        "decision": "ask",
        "tools": {
          "read_file": "allow",
          "write_file": "ask",
          "delete_file": "deny"
        }
      }
    }
  }
}
```

## Recommended Guardrails

- Ask before repository-mutating shell commands such as reset, clean, install, or publish.
- Deny credential folders and sensitive dotfiles through filesystem policy.
- Keep desktop approvals running for queued MCP ask decisions.
- Review repeated approvals with `agentfence policy suggest` before broadening policy.

## Verification

```bash
agentfence check --actor claude-code -- git status
agentfence filesystem check --operation read --path ~/.ssh/id_rsa
agentfence policy suggest --threshold 3 --limit 1000
```
