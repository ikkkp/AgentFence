# Security Policy

## Supported Versions

AgentFence is pre-1.0. Security fixes are shipped on `main` and included in the next tagged release.

## Reporting a Vulnerability

Please report vulnerabilities through GitHub private vulnerability reporting or a GitHub Security Advisory for this repository. Do not include secrets, tokens, private audit logs, or proprietary policy files in public issues.

Helpful reports include:

- AgentFence version or commit SHA.
- Operating system and shell.
- The command, MCP call, or policy path involved.
- Whether the issue affects CLI, daemon, desktop, release packaging, or website.
- A minimal reproduction that uses synthetic secrets and test files.

## Current Boundary

AgentFence enforces actions routed through its CLI wrappers, guarded shell modes, MCP proxies, and daemon APIs. OS-level filesystem isolation and full network proxy enforcement are not yet default security boundaries; use `agentfence boundary inspect` to review local helper availability and keep sensitive paths denied or ask-gated in policy.

## Supply Chain

CI runs formatting, tests, smoke checks, release packaging checks, RustSec advisory audit, and a critical-level npm advisory audit. Dependabot tracks Cargo, pnpm, and GitHub Actions updates.
