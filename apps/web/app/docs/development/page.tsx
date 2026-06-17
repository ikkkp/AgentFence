import { sitePath } from "../../site-path";

export default function DevelopmentPage() {
  return (
    <main className="page">
      <a className="back" href={sitePath("/docs")}>Project Documentation</a>
      <h1>Development Workflow</h1>
      <p>
        Use this workflow when changing AgentFence locally. The repository combines a Rust workspace with
        a pnpm/Turborepo frontend workspace.
      </p>
      <h2>Requirements</h2>
      <ul>
        <li>Rust 1.85+</li>
        <li>Node.js 18+ for local development, Node.js 24 in the GitHub Pages workflow</li>
        <li>pnpm 10+</li>
      </ul>
      <h2>Common commands</h2>
      <pre>{`pnpm install
cargo fmt --check
cargo test
pnpm typecheck
pnpm build
pnpm --filter @agentfence/web dev
pnpm --filter @agentfence/desktop dev`}</pre>
      <h2>Local services</h2>
      <ul>
        <li>Website dev server: `http://127.0.0.1:37430`</li>
        <li>Desktop dev server: `http://127.0.0.1:37420`</li>
        <li>Daemon API: `http://127.0.0.1:37421`</li>
      </ul>
      <h2>GitHub Pages export</h2>
      <pre>{`$env:GITHUB_PAGES = "true"
$env:NEXT_PUBLIC_BASE_PATH = "/AgentFence"
$env:NEXT_PUBLIC_SITE_URL = "https://ikkkp.github.io/AgentFence"
pnpm --filter @agentfence/web build`}</pre>
      <p>The exported static site is written to `apps/web/out`.</p>
    </main>
  );
}
