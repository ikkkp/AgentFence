# Policy

AgentFence policies are JSON files named `agentfence.policy.json`. The policy is intended to be deterministic, reviewable, and version-controlled.

## Core Fields

```json
{
  "version": "0.1",
  "project": "my-project",
  "defaultDecision": "ask",
  "actors": {},
  "shell": {},
  "filesystem": {},
  "network": {},
  "mcp": {},
  "skills": {},
  "approval": {},
  "audit": {}
}
```

## Decisions

Supported decisions:

- `allow`
- `deny`
- `ask`
- `allow_once`
- `allow_for_session`
- `allow_with_constraints`

## Shell Rules

Shell rules match command names, command prefixes, text patterns, and risk levels.

```json
{
  "id": "ask-package-install",
  "match": {
    "commands": ["npm install", "pnpm install", "pip install"],
    "risks": ["high"]
  },
  "decision": "ask",
  "reason": "package installation can modify the environment"
}
```

Risk levels:

- `low`: read-only or low-impact inspection
- `medium`: ordinary development command
- `high`: environment-changing, publishing, or repository-changing command
- `critical`: destructive, privileged, or remote-code-execution command

## MCP Rules

MCP rules control server availability and per-tool/resource/prompt decisions.

```json
{
  "mcp": {
    "servers": {
      "github": {
        "enabled": true,
        "decision": "ask",
        "rateLimit": {
          "enabled": true,
          "maxRequests": 30,
          "windowSeconds": 60
        },
        "tools": {
          "list_pull_requests": "allow",
          "create_pull_request": "ask",
          "merge_pull_request": "deny"
        }
      }
    }
  }
}
```

`rateLimit` is enforced by `agentfence mcp proxy` before a permitted call reaches the upstream server.

## Filesystem Rules

Filesystem rules define allowed roots, denied sensitive paths, and write behavior.

```json
{
  "filesystem": {
    "allowRoots": ["./"],
    "denyPaths": ["~/.ssh", "~/.aws", ".env", "secrets.json"],
    "write": {
      "decision": "ask",
      "allowExtensions": [".rs", ".ts", ".md", ".json"]
    }
  }
}
```

Check a path:

```bash
agentfence filesystem check --operation read --path ~/.ssh/id_rsa
```

## Network Rules

Network rules allow or deny domains and provide a default decision for unknown domains.

```bash
agentfence network check --domain github.com
agentfence network check --domain https://transfer.sh/file
```

## Skill Rules

Skill rules allow, deny, or ask for named agent capabilities.

```bash
agentfence skill check --name code-review
agentfence skill check --name deploy-production
```

## Validation

Validate a policy:

```bash
agentfence policy validate agentfence.policy.json
```

Print the generated schema:

```bash
agentfence policy schema
```

The checked-in schema lives at `schemas/agentfence.policy.schema.json`.

## Policy Assistant

The policy assistant generates JSON Patch proposals from natural-language instructions. It does not apply changes automatically.

```bash
agentfence policy ask "allow tests but ask before dependency installs"
```

Example output:

```json
{
  "summary": "Generated 2 policy patch operation(s) from the instruction.",
  "operations": [
    {
      "op": "add",
      "path": "/shell/rules/-",
      "value": {
        "id": "allow-local-tests",
        "decision": "allow"
      }
    }
  ]
}
```

Apply a proposal after confirmation:

```bash
agentfence policy apply "deny production deploy"
```

Apply without an interactive prompt:

```bash
agentfence policy apply --yes "deny production deploy"
```

`policy apply` prints the proposed operations first, applies them to the policy JSON, then validates the patched policy before writing it back.

## Policy Simulator

Use the simulator to explain hypothetical actions without creating approval requests or audit rows:

```bash
agentfence simulate shell -- git status https://transfer.sh/file
```

The output includes the shell decision, network-domain decisions, the effective decision, and an explanation chain.

## Presets

AgentFence ships with policy presets for common modes:

- `read-only`
- `developer`
- `strict`
- `trusted-project`
- `ci-like`

Use a preset during initialization:

```bash
agentfence init --preset strict
```

## Policy Bundles

Policy bundles are portable JSON artifacts for team templates and signed policies. They include the policy, a SHA-256 digest, and optional Ed25519 signature metadata.

```bash
agentfence policy bundle keygen --output bundle-key.json
agentfence policy bundle export --output team.bundle.json --name "Team Policy"
agentfence policy bundle sign team.bundle.json --key bundle-key.json
agentfence policy bundle verify team.bundle.json
agentfence policy bundle import team.bundle.json --yes --require-signature
```

`verify` checks both digest integrity and signature validity when a signature is present. `--require-signature` prevents importing unsigned bundles.
