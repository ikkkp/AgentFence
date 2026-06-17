import { sitePath } from "../site-path";

export default function DownloadPage() {
  const releaseUrl = "https://github.com/ikkkp/AgentFence/releases/tag/v0.1.0";
  const artifactBase = "https://github.com/ikkkp/AgentFence/releases/download/v0.1.0";

  return (
    <main className="page">
      <a className="back" href={sitePath("/")}>AgentFence</a>
      <h1>Download</h1>
      <p>
        AgentFence v0.1.0 publishes CLI, daemon, checksum, and desktop artifacts through GitHub
        Releases. Download the archive for your platform, verify the `.checksums.json` manifest,
        then run the installer from the extracted archive.
      </p>
      <p>
        Release page: <a href={releaseUrl}>v0.1.0 on GitHub Releases</a>.
      </p>
      <h2>Release archives</h2>
      <ul>
        <li><a href={`${artifactBase}/agentfence-windows-x64.zip`}>agentfence-windows-x64.zip</a></li>
        <li><a href={`${artifactBase}/agentfence-macos-arm64.zip`}>agentfence-macos-arm64.zip</a></li>
        <li><a href={`${artifactBase}/agentfence-linux-x64.zip`}>agentfence-linux-x64.zip</a></li>
      </ul>
      <p>
        CLI archives include `agentfence`, `agentfenced`, the default policy, and installer scripts
        that copy binaries into a user bin directory and register it on PATH. Each CLI archive is
        published with a `.checksums.json` manifest containing its SHA256 digest.
      </p>
      <pre>{`# Windows
.\\install.ps1

# macOS/Linux
./install.sh`}</pre>
      <h2>Build from source</h2>
      <pre>{`git clone https://github.com/ikkkp/AgentFence.git
cd AgentFence
cargo run --bin agentfence -- policy validate agentfence.policy.json`}</pre>
    </main>
  );
}
