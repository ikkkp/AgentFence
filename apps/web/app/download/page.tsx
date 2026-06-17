import { sitePath } from "../site-path";

export default function DownloadPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/")}>AgentFence</a>
      <h1>Download</h1>
      <p>
        Tagged releases produce CLI, daemon, and desktop artifacts. Until the first public release is
        attached on GitHub, build from source and run the local control plane directly.
      </p>
      <pre>{`git clone https://github.com/ikkkp/AgentFence.git
cd AgentFence
cargo run --bin agentfence -- policy validate agentfence.policy.json`}</pre>
      <h2>Release archives</h2>
      <p>
        CLI archives include `agentfence`, `agentfenced`, the default policy, and installer scripts
        that copy binaries into a user bin directory and register it on PATH. Each CLI archive is
        published with a `.checksums.json` manifest containing its SHA256 digest.
      </p>
      <pre>{`# Windows
.\\install.ps1

# macOS/Linux
./install.sh`}</pre>
    </main>
  );
}
