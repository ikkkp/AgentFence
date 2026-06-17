# Release and Packaging

AgentFence publishes two release artifact families:

- CLI and daemon archives containing `agentfence`, `agentfenced`, `README.md`, the default policy, and installer scripts.
- Desktop bundles produced by Tauri for Windows, macOS, and Linux.

## Local Release Check

Run the full verification matrix before tagging:

```bash
cargo fmt --check
cargo test
pnpm typecheck
pnpm build
```

Then run the product smoke suite:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/smoke.ps1
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

CLI archives include:

- `install.ps1`: copies `agentfence.exe` and `agentfenced.exe` to `%LOCALAPPDATA%\AgentFence\bin` and adds that directory to the user PATH unless `-SkipPath` is passed.
- `install.sh`: copies `agentfence` and `agentfenced` to `$HOME/.local/bin` and appends that directory to `$HOME/.profile` when needed.

## GitHub Release Flow

Create a version tag to trigger `.github/workflows/release.yml`:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Use `docs/release-notes/v0.1.0.md` as the release body and update the website download page when a new version is published.

The workflow builds:

- `agentfence-windows-x64.zip`
- `agentfence-macos-arm64.zip`
- `agentfence-linux-x64.zip`
- `agentfence-<platform>.checksums.json` SHA256 manifests for each CLI archive.
- `agentfence-desktop-windows-x64`
- `agentfence-desktop-macos-arm64`
- `agentfence-desktop-linux-x64`

Generate a local checksum manifest for staged artifacts:

```powershell
.\packaging\release-manifest.ps1 -ArtifactPath .\dist\agentfence-windows-x64.zip -Output .\dist\agentfence-windows-x64.checksums.json
```

Package the local CLI and daemon release archive with the same staging layout used by CI:

```powershell
cargo build --release --bin agentfence --bin agentfenced
.\packaging\package-cli.ps1 -Name windows-x64 -ExeSuffix .exe -Version v0.1.0 -Repository ikkkp/AgentFence -Commit (git rev-parse HEAD)
```

Each manifest records the release version, repository, commit, artifact size, and SHA256 digest. These manifests are not a replacement for future certificate-backed signing or notarization, but they give users a deterministic checksum to compare after download.

Tag-triggered release builds attach CLI archives, checksum manifests, and desktop bundles to the GitHub release automatically.

After downloading a CLI archive, users can install the binaries onto PATH:

```powershell
.\install.ps1
```

```bash
./install.sh
```

For v0.1.x, attach the generated artifacts to a GitHub release and include the current security boundary:

- Shell commands are enforced when launched through `agentfence run` or entered in `agentfence shell`.
- URL-like and common Git/SSH remotes found in guarded shell commands are checked against network policy before execution.
- MCP stdio calls are enforced through `agentfence mcp proxy`; HTTP JSON-RPC, GET/SSE stream requests, chunked JSON list filtering, and SSE list filtering are routed through `agentfence mcp http-proxy`.
- Filesystem, network, skill, and MCP checks are available through the daemon API.
- OS-level network and filesystem interception remain future hardening items.
