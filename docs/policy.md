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

`rateLimit` is enforced by `agentfence mcp proxy` and `agentfence mcp http-proxy` before a permitted call reaches the upstream server.

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

## Policy Rule Library

Reusable rule packs provide reviewable JSON Patch proposals for common workflows. Use `show` to inspect a pack before applying it.

```bash
agentfence policy library list
agentfence policy library show local-tests
agentfence policy library apply release-guard --yes
```

Included packs:

- `local-tests`: allow common local build, format, lint, and test commands.
- `dependency-installs`: ask before package or toolchain installation commands.
- `release-guard`: deny production deploy commands and deployment skills.
- `github-readonly-mcp`: allow common GitHub read tools, ask for PR creation, and deny merge/release tools.
- `network-strict`: deny unknown network domains while keeping common registries explicit.

## Review Presets

Review presets combine multiple rule packs into one reviewable proposal for common agent profiles.

```bash
agentfence policy review-preset list
agentfence policy review-preset show codex-balanced
agentfence policy review-preset apply release-hardening --yes
agentfence policy review-preset export release-hardening --output release-hardening.review.json
agentfence policy review-preset verify release-hardening.review.json
agentfence policy bundle keygen --output bundle-key.json
agentfence policy review-preset sign release-hardening.review.json --key bundle-key.json
agentfence policy review-preset trust add --name platform --key <public-key> --expires-at 2027-01-01T00:00:00Z
agentfence policy review-preset trust list
agentfence policy review-preset trust revoke --key <public-key> --reason rotated
agentfence policy review-preset import release-hardening.review.json --yes
agentfence policy review-preset verify release-hardening.review.json --require-signature --trusted-key <public-key>
agentfence policy review-preset import release-hardening.review.json --yes --require-signature --trusted-key <public-key>
agentfence policy review-preset verify release-hardening.review.json --require-signature --trust-store .agentfence/trusted-review-keys.json
agentfence policy review-preset import release-hardening.review.json --yes --require-signature --trust-store .agentfence/trusted-review-keys.json
```

Included presets:

- `codex-balanced`: local tests, dependency install review, and GitHub read-oriented MCP defaults.
- `release-hardening`: production deploy denial, strict unknown-network handling, and gated GitHub writes.
- `readonly-mcp`: read-oriented MCP defaults with strict unknown-network handling.

Exported review presets are JSON artifacts containing metadata, a digest, and a standard policy patch proposal. Teams can review them in version control before importing them into a project policy. Use `sign`, `--require-signature`, and one or more `--trusted-key` values when a team wants Ed25519 verification against accepted public keys before import. Use `review-preset trust add` to maintain a local `.agentfence/trusted-review-keys.json` trust store and pass it with `--trust-store` during verification or import. Trust store entries support `status`, `addedAt`, optional `expiresAt`, `revokedAt`, and `revocationReason`; revoked or expired keys are ignored during verification.

## Audit-Driven Suggestions

AgentFence can scan recent audit events and suggest narrower policy rules for actions that were repeatedly approved after an `ask` decision. Suggestions are emitted as JSON Patch proposals and are not applied automatically.

```bash
agentfence policy suggest --threshold 3 --limit 1000
agentfence policy suggest --audit .agentfence/audit.sqlite --output suggestions.json
```

The first implementation suggests exact command allow rules, exact MCP tool/resource/prompt allow entries, exact network `allowDomains` additions, and exact skill allow entries. It only uses events where the action was allowed but the original recorded policy decision was `ask`.

The daemon exposes the same report for desktop and local integrations:

```bash
curl "http://127.0.0.1:37421/policy/suggestions?threshold=3&limit=1000"
```

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

## Organization Templates

Organization templates are built-in starting points for team policy distribution. Export one to a policy file, review it in version control, then optionally sign it as a policy bundle.

```bash
agentfence policy template list
agentfence policy template show engineering-default
agentfence policy template export release-guard --output agentfence.policy.json --force
```

Included templates:

- `engineering-default`: balanced local development guardrails for coding agents.
- `read-only-audit`: strict read-only policy with audit logging enabled.
- `release-guard`: stricter release-branch policy that denies direct publishing and production-like actions.

## Policy Bundles

Policy bundles are portable JSON artifacts for team templates and signed policies. They include the policy, a SHA-256 digest, and optional Ed25519 signature metadata.

```bash
agentfence policy bundle keygen --output bundle-key.json
agentfence policy bundle export --output team.bundle.json --name "Team Policy"
agentfence policy bundle sign team.bundle.json --key bundle-key.json
agentfence policy bundle verify team.bundle.json
agentfence policy bundle manifest team.bundle.json --output team.manifest.json
agentfence policy bundle import team.bundle.json --yes --require-signature
```

`verify` checks both digest integrity and signature validity when a signature is present. `manifest` emits a transparency JSON artifact with the bundle identity, policy digest, signature public key, signature digest, and verification result for team distribution records. `--require-signature` prevents importing unsigned bundles.
