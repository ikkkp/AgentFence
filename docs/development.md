# Development

## Requirements

- Rust 1.85+
- Node.js 18+
- pnpm 10+

## Install

```bash
pnpm install
```

## Rust

```bash
cargo fmt --check
cargo test
cargo run --bin agentfence -- policy validate agentfence.policy.json
cargo run --bin agentfence -- policy ask "allow tests but ask before dependency installs"
cargo run --bin agentfence -- policy apply --yes "deny production deploy"
cargo run --bin agentfence -- policy library list
cargo run --bin agentfence -- policy review-preset list
cargo run --bin agentfence -- policy template list
cargo run --bin agentfence -- policy bundle keygen --output bundle-key.json
cargo run --bin agentfence -- policy bundle export --output team.bundle.json
cargo run --bin agentfence -- policy bundle sign team.bundle.json --key bundle-key.json
cargo run --bin agentfence -- audit export --format csv --limit 100
cargo run --bin agentfence -- approvals list
cargo run --bin agentfence -- shell --actor codex
cargo run --bin agentfence -- filesystem check --operation read --path ~/.ssh/id_rsa
cargo run --bin agentfence -- network check --domain github.com
cargo run --bin agentfence -- skill check --name code-review
cargo run --bin agentfence -- mcp proxy --server github -- node path/to/server.js
cargo run --bin agentfence -- mcp http-proxy --server github --upstream http://127.0.0.1:3000/mcp
cargo run --bin agentfenced -- --listen 127.0.0.1:37421
```

## Frontend

```bash
pnpm typecheck
pnpm build
pnpm --filter @agentfence/desktop dev
pnpm --filter @agentfence/web dev
```

The desktop development server uses `http://127.0.0.1:37420`.
The website development server uses `http://127.0.0.1:37430`.
The daemon uses `http://127.0.0.1:37421`.

## Release Packaging

```bash
cargo build --release --bin agentfence --bin agentfenced
pnpm --filter @agentfence/desktop tauri:build
```

Tag pushes matching `v*` run the release workflow. See `docs/release.md`.

## Verification Matrix

Before opening a pull request, run:

```bash
cargo fmt --check
cargo test
pnpm typecheck
pnpm build
```
