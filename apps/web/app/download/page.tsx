export default function DownloadPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence</a>
      <h1>Download</h1>
      <p>
        Tagged releases produce CLI, daemon, and desktop artifacts. Until the first public release is
        attached on GitHub, build from source and run the local control plane directly.
      </p>
      <pre>{`git clone https://github.com/ikkkp/AgentFence.git
cd AgentFence
cargo run --bin agentfence -- policy validate agentfence.policy.json`}</pre>
    </main>
  );
}
