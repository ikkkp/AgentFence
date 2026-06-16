export default function PolicyPage() {
  return (
    <main className="page">
      <a className="back" href="/">AgentFence Docs</a>
      <h1>Policy JSON</h1>
      <p>
        AgentFence policies describe actor trust, shell command rules, filesystem boundaries, network
        preferences, MCP access, skill access, approval behavior, and audit storage.
      </p>
      <pre>{`{
  "version": "0.1",
  "defaultDecision": "ask",
  "shell": {
    "rules": [
      {
        "id": "allow-readonly",
        "match": { "commands": ["git status", "git diff"] },
        "decision": "allow"
      }
    ]
  }
}`}</pre>
      <h2>Other checks</h2>
      <pre>{`agentfence filesystem check --operation read --path ~/.ssh/id_rsa
agentfence network check --domain github.com
agentfence skill check --name code-review`}</pre>
      <h2>Policy assistant</h2>
      <p>
        The assistant produces JSON Patch proposals. It does not apply policy changes automatically.
      </p>
      <pre>{`agentfence policy ask "allow tests but ask before dependency installs"`}</pre>
      <p>
        Policy changes can be applied after confirmation, and the patched JSON is validated before it is written.
      </p>
      <pre>{`agentfence policy apply "deny production deploy"`}</pre>
      <h2>Rule library</h2>
      <p>
        Reusable rule packs provide reviewable JSON Patch proposals for common workflows.
      </p>
      <pre>{`agentfence policy library list
agentfence policy library show local-tests
agentfence policy library apply release-guard --yes`}</pre>
      <h2>Review presets</h2>
      <p>
        Review presets combine multiple rule packs into one JSON Patch proposal.
      </p>
      <pre>{`agentfence policy review-preset list
agentfence policy review-preset show codex-balanced
agentfence policy review-preset apply release-hardening --yes
agentfence policy review-preset export release-hardening --output release-hardening.review.json
agentfence policy review-preset verify release-hardening.review.json
agentfence policy review-preset sign release-hardening.review.json --key bundle-key.json
agentfence policy review-preset trust add --name platform --key <public-key> --expires-at 2027-01-01T00:00:00Z
agentfence policy review-preset trust list
agentfence policy review-preset trust revoke --key <public-key> --reason rotated
agentfence policy review-preset verify release-hardening.review.json --require-signature --trust-store .agentfence/trusted-review-keys.json
agentfence policy review-preset import release-hardening.review.json --yes --require-signature --trust-store .agentfence/trusted-review-keys.json`}</pre>
      <p>
        Audit-driven suggestions scan repeated approved ask decisions and emit narrower JSON Patch proposals.
      </p>
      <pre>{`agentfence policy suggest --threshold 3 --limit 1000`}</pre>
      <h2>Policy simulator</h2>
      <p>
        Simulate hypothetical shell actions without creating approvals or audit rows.
      </p>
      <pre>{`agentfence simulate shell -- git status https://transfer.sh/file`}</pre>
      <h2>Templates</h2>
      <p>
        Organization templates provide built-in starting points for team policy distribution.
      </p>
      <pre>{`agentfence policy template list
agentfence policy template show engineering-default
agentfence policy template export release-guard --output agentfence.policy.json --force`}</pre>
      <h2>Presets and bundles</h2>
      <pre>{`agentfence init --preset strict
agentfence policy bundle keygen --output bundle-key.json
agentfence policy bundle export --output team.bundle.json
agentfence policy bundle sign team.bundle.json --key bundle-key.json
agentfence policy bundle verify team.bundle.json
agentfence policy bundle manifest team.bundle.json --output team.manifest.json
agentfence policy bundle import team.bundle.json --yes --require-signature`}</pre>
    </main>
  );
}
