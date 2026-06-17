import { sitePath } from "../../site-path";

export default function ReleasePage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/docs")}>Project Documentation</a>
      <h1>Release and Packaging</h1>
      <p>
        AgentFence publishes CLI/daemon archives and desktop bundles. The release workflow runs on tags
        matching `v*`.
      </p>
      <h2>Local release check</h2>
      <pre>{`cargo fmt --check
cargo test
pnpm typecheck
pnpm build
cargo build --release --bin agentfence --bin agentfenced
pnpm --filter @agentfence/desktop tauri:build`}</pre>
      <h2>CLI archives</h2>
      <p>
        CLI archives include `agentfence`, `agentfenced`, the default policy, README, installer scripts,
        and SHA256 checksum manifests.
      </p>
      <pre>{`./install.sh

# Windows
.\\install.ps1`}</pre>
      <h2>GitHub release flow</h2>
      <pre>{`git tag v0.1.0
git push origin v0.1.0`}</pre>
      <p>
        Release artifacts are produced by `.github/workflows/release.yml`. Checksum manifests are generated
        by `packaging/release-manifest.ps1`.
      </p>
    </main>
  );
}
