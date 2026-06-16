# Release and Packaging

AgentFence publishes two release artifact families:

- CLI and daemon archives containing `agentfence`, `agentfenced`, `README.md`, and the default policy.
- Desktop bundles produced by Tauri for Windows, macOS, and Linux.

## Local Release Check

Run the full verification matrix before tagging:

```bash
cargo fmt --check
cargo test
pnpm typecheck
pnpm build
```

Build local release binaries:

```bash
cargo build --release --bin agentfence --bin agentfenced
```

Build the desktop app:

```bash
pnpm install
pnpm --filter @agentfence/desktop tauri:build
```

The Rust binaries are written to `target/release`.
The desktop executable and installers are written under `target/release`.

## GitHub Release Flow

Create a version tag to trigger `.github/workflows/release.yml`:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow builds:

- `agentfence-windows-x64.zip`
- `agentfence-macos-arm64.zip`
- `agentfence-linux-x64.zip`
- `agentfence-desktop-windows-x64`
- `agentfence-desktop-macos-arm64`
- `agentfence-desktop-linux-x64`

For v0.1.x, attach the generated artifacts to a GitHub release and include the current security boundary:

- Shell commands are enforced when launched through `agentfence run`.
- URL-like and common Git/SSH remotes found in guarded shell commands are checked against network policy before execution.
- MCP stdio calls are enforced through `agentfence mcp proxy`; non-streaming HTTP JSON-RPC calls are enforced through `agentfence mcp http-proxy`.
- Filesystem, network, skill, and MCP checks are available through the daemon API.
- OS-level network and filesystem interception remain future hardening items.
