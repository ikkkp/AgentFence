import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import type { ApprovalRequest, AuditEvent, ShellSimulationOutput } from "@agentfence/types";
import {
  Activity,
  Bell,
  Check,
  CheckCircle2,
  FileJson,
  History,
  Plug,
  RefreshCw,
  Save,
  Shield,
  X
} from "lucide-react";
import "./styles.css";

const daemonBase = "http://127.0.0.1:37421";
type AuditDecisionFilter = "all" | "allow" | "deny" | "ask";

const fallbackApprovals: ApprovalRequest[] = [
  {
    id: "apr_101",
    actor: "codex",
    action: "shell.exec",
    subject: "pnpm install",
    risk: "high",
    reason: "package installation can modify the environment"
  },
  {
    id: "apr_102",
    actor: "claude-code",
    action: "mcp.tool",
    subject: "github/create_pull_request",
    risk: "medium",
    reason: "creating a pull request requires approval"
  }
];

const fallbackAudit: AuditEvent[] = [
  {
    id: "audit_101",
    timestamp: new Date().toISOString(),
    actor: "codex",
    action: "shell.exec",
    subject: "git status --short",
    decision: "allow",
    risk: "low",
    reason: "read-only inspection is allowed"
  },
  {
    id: "audit_102",
    timestamp: new Date().toISOString(),
    actor: "codex",
    action: "shell.exec",
    subject: "rm -rf /",
    decision: "deny",
    risk: "critical",
    reason: "dangerous broad deletion is denied"
  },
  {
    id: "audit_103",
    timestamp: new Date().toISOString(),
    actor: "claude-code",
    action: "filesystem.write",
    subject: "filesystem/write_file",
    decision: "ask",
    risk: "medium",
    reason: "filesystem write-like operation requires policy decision"
  }
];

const policyPreview = `{
  "version": "0.1",
  "project": "AgentFence",
  "defaultDecision": "ask",
  "shell": {
    "rules": [
      {
        "id": "allow-readonly",
        "decision": "allow"
      },
      {
        "id": "deny-dangerous-delete",
        "decision": "deny"
      }
    ]
  }
}`;

function App() {
  const [daemon, setDaemon] = useState<"checking" | "ready" | "offline">("checking");
  const [approvals, setApprovals] = useState<ApprovalRequest[]>(fallbackApprovals);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>(fallbackAudit);
  const [auditActorFilter, setAuditActorFilter] = useState("");
  const [auditActionFilter, setAuditActionFilter] = useState("");
  const [auditDecisionFilter, setAuditDecisionFilter] = useState<AuditDecisionFilter>("all");
  const [policyInstruction, setPolicyInstruction] = useState("allow tests but ask before dependency installs");
  const [policyProposal, setPolicyProposal] = useState(policyPreview);
  const [policyText, setPolicyText] = useState(policyPreview);
  const [policyStatus, setPolicyStatus] = useState("Sample policy loaded");
  const [policyStatusKind, setPolicyStatusKind] = useState<"neutral" | "valid" | "invalid">("neutral");
  const [policyDirty, setPolicyDirty] = useState(false);
  const [simulatorInput, setSimulatorInput] = useState("git status https://transfer.sh/file");
  const [simulatorResult, setSimulatorResult] = useState<ShellSimulationOutput | null>(null);
  const [simulatorStatus, setSimulatorStatus] = useState("Ready");
  const [bundleDigest, setBundleDigest] = useState("not loaded");
  const [bundleSignature, setBundleSignature] = useState("not checked");
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission | "unsupported">("unsupported");

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${daemonBase}/health`, { signal: controller.signal })
      .then((response) => {
        setDaemon(response.ok ? "ready" : "offline");
      })
      .catch(() => setDaemon("offline"));
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if ("Notification" in window) {
      setNotificationPermission(Notification.permission);
    }
    refreshApprovals();
    refreshPolicy();
    refreshBundleDigest();
    const timer = window.setInterval(() => {
      refreshApprovals();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [notificationPermission]);

  useEffect(() => {
    refreshAudit();
    const timer = window.setInterval(refreshAudit, 5000);
    return () => window.clearInterval(timer);
  }, [auditActorFilter, auditActionFilter, auditDecisionFilter]);

  async function refreshApprovals() {
    try {
      const response = await fetch(`${daemonBase}/approvals?status=pending`);
      if (!response.ok) {
        return;
      }
      const pending = (await response.json()) as ApprovalRequest[];
      setApprovals((current) => {
        if (notificationPermission === "granted" && pending.length > current.length) {
          const known = new Set(current.map((item) => item.id));
          const newest = pending.find((item) => !known.has(item.id)) ?? pending[0];
          if (newest) {
            new Notification("AgentFence approval required", {
              body: `${newest.actor} ${newest.action}: ${newest.subject}`
            });
          }
        }
        return pending;
      });
    } catch {
      setApprovals(fallbackApprovals);
    }
  }

  async function resolveApproval(id: string, decision: "allowed" | "denied") {
    await fetch(`${daemonBase}/approvals/${id}/resolve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        decision,
        responder: "desktop-ui"
      })
    });
    await refreshApprovals();
  }

  async function refreshAudit() {
    const params = new URLSearchParams({ limit: "20" });
    const actor = auditActorFilter.trim();
    const action = auditActionFilter.trim();
    if (actor) {
      params.set("actor", actor);
    }
    if (action) {
      params.set("action", action);
    }
    if (auditDecisionFilter !== "all") {
      params.set("decision", auditDecisionFilter);
    }

    try {
      const response = await fetch(`${daemonBase}/audit?${params.toString()}`);
      if (!response.ok) {
        return;
      }
      setAuditEvents((await response.json()) as AuditEvent[]);
    } catch {
      setAuditEvents(fallbackAudit);
    }
  }

  async function refreshPolicy() {
    try {
      const response = await fetch(`${daemonBase}/policy`);
      if (!response.ok) {
        return;
      }
      const policy = await response.json();
      setPolicyText(JSON.stringify(policy, null, 2));
      setPolicyStatus("Policy loaded from daemon");
      setPolicyStatusKind("valid");
      setPolicyDirty(false);
    } catch {
      setPolicyText(policyPreview);
      setPolicyStatus("Daemon offline; showing sample policy");
      setPolicyStatusKind("neutral");
    }
  }

  async function draftPolicyPatch() {
    try {
      const response = await fetch(`${daemonBase}/policy/ask`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ instruction: policyInstruction })
      });
      if (!response.ok) {
        return;
      }
      setPolicyProposal(JSON.stringify(await response.json(), null, 2));
    } catch {
      setPolicyProposal(policyPreview);
    }
  }

  async function validatePolicy() {
    let parsed: unknown;
    try {
      parsed = JSON.parse(policyText);
    } catch (error) {
      setPolicyStatus(error instanceof Error ? error.message : "Invalid JSON");
      setPolicyStatusKind("invalid");
      return false;
    }

    try {
      const response = await fetch(`${daemonBase}/policy/validate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(parsed)
      });
      const result = (await response.json()) as { valid: boolean; error?: string };
      setPolicyStatus(result.valid ? "Policy JSON is valid" : result.error ?? "Policy is invalid");
      setPolicyStatusKind(result.valid ? "valid" : "invalid");
      return result.valid;
    } catch {
      setPolicyStatus("Daemon offline; policy was parsed locally only");
      setPolicyStatusKind("neutral");
      return true;
    }
  }

  async function savePolicy() {
    let parsed: unknown;
    try {
      parsed = JSON.parse(policyText);
    } catch (error) {
      setPolicyStatus(error instanceof Error ? error.message : "Invalid JSON");
      setPolicyStatusKind("invalid");
      return;
    }

    const response = await fetch(`${daemonBase}/policy`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(parsed)
    });
    if (!response.ok) {
      setPolicyStatus("Policy save failed");
      setPolicyStatusKind("invalid");
      return;
    }
    setPolicyStatus("Policy saved");
    setPolicyStatusKind("valid");
    setPolicyDirty(false);
    await refreshBundleDigest();
  }

  async function enableNotifications() {
    if (!("Notification" in window)) {
      setNotificationPermission("unsupported");
      return;
    }
    const permission = await Notification.requestPermission();
    setNotificationPermission(permission);
  }

  async function runSimulator() {
    const command = parseCommandLine(simulatorInput);
    if (command.length === 0) {
      setSimulatorStatus("Enter a command to simulate");
      return;
    }

    try {
      const response = await fetch(`${daemonBase}/simulate/shell`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          actor: "codex",
          command
        })
      });
      if (!response.ok) {
        setSimulatorStatus("Simulation failed");
        return;
      }
      setSimulatorResult((await response.json()) as ShellSimulationOutput);
      setSimulatorStatus("Simulation complete");
    } catch {
      setSimulatorStatus("Daemon offline");
    }
  }

  async function refreshBundleDigest() {
    try {
      const response = await fetch(`${daemonBase}/policy/bundle?name=DesktopBundle`);
      if (!response.ok) {
        return;
      }
      const bundle = await response.json();
      setBundleDigest(bundle.digest ?? "missing digest");
      setBundleSignature(bundle.signature ? "signed" : "unsigned");
    } catch {
      setBundleDigest("offline");
      setBundleSignature("offline");
    }
  }

  const activeAgents = new Set([
    ...approvals.map((item) => item.actor),
    ...auditEvents.map((item) => item.actor)
  ]);
  const deniedCount = auditEvents.filter((item) => item.decision === "deny").length;

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Shield size={26} />
          <div>
            <strong>AgentFence</strong>
            <span>Local permission gateway</span>
          </div>
        </div>
        <nav>
          <a className="active"><Activity size={18} />Dashboard</a>
          <a><Check size={18} />Approvals</a>
          <a><History size={18} />Audit</a>
          <a><FileJson size={18} />Policy</a>
          <a><Plug size={18} />MCP & Skills</a>
        </nav>
      </aside>

      <section className="content">
        <header className="topbar">
          <div>
            <p>Desktop Control Plane</p>
            <h1>Live local agent permissions</h1>
          </div>
          <div className="topbar-actions">
            <button className="text-button" onClick={enableNotifications}>
              <Bell size={15} />{notificationPermission === "granted" ? "Notifications on" : "Enable alerts"}
            </button>
            <span className={`daemon daemon-${daemon}`}>Daemon {daemon} - localhost:37421</span>
          </div>
        </header>

        <section className="metrics" aria-label="Permission summary">
          <Metric label="Active agents" value={String(activeAgents.size)} detail={Array.from(activeAgents).join(", ") || "none observed"} />
          <Metric label="Pending approvals" value={String(approvals.length)} detail={`${approvals.filter((item) => item.risk === "high").length} high risk`} />
          <Metric label="Denied recent" value={String(deniedCount)} detail="from local audit" />
          <Metric label="Audit events" value={String(auditEvents.length)} detail="latest local rows" />
        </section>

        <section className="grid">
          <Panel title="Live Approvals" icon={<Check size={18} />}>
            <div className="approval-list">
              {approvals.length === 0 ? (
                <div className="empty-state">No pending approvals</div>
              ) : approvals.map((item) => (
                <article className="approval" key={item.id}>
                  <div>
                    <span className={`risk risk-${item.risk}`}>{item.risk}</span>
                    <strong>{item.subject}</strong>
                    <p>{item.actor} - {item.action}</p>
                    <small>{item.reason}</small>
                  </div>
                  <div className="approval-actions">
                    <button className="icon-button allow" aria-label="Allow once" onClick={() => resolveApproval(item.id, "allowed")}><Check size={16} /></button>
                    <button className="icon-button deny" aria-label="Deny" onClick={() => resolveApproval(item.id, "denied")}><X size={16} /></button>
                  </div>
                </article>
              ))}
            </div>
          </Panel>

          <Panel title="Policy Editor" icon={<FileJson size={18} />}>
            <div className="assistant-row">
              <input
                value={policyInstruction}
                onChange={(event) => setPolicyInstruction(event.target.value)}
                aria-label="Policy instruction"
              />
              <button onClick={draftPolicyPatch}>Draft</button>
            </div>
            <pre className="policy policy-patch">{policyProposal}</pre>
            <div className="policy-toolbar">
              <button className="text-button" onClick={refreshPolicy}><RefreshCw size={15} />Reload</button>
              <button className="text-button" onClick={validatePolicy}><CheckCircle2 size={15} />Validate</button>
              <button className="text-button primary" onClick={savePolicy} disabled={!policyDirty}><Save size={15} />Save</button>
            </div>
            <textarea
              className="policy-editor"
              value={policyText}
              onChange={(event) => {
                setPolicyText(event.target.value);
                setPolicyDirty(true);
                setPolicyStatus("Policy has unsaved changes");
                setPolicyStatusKind("neutral");
              }}
              aria-label="Policy JSON"
              spellCheck={false}
            />
            <div className={`status status-${policyStatusKind}`}>{policyStatus}</div>
          </Panel>

          <Panel title="Policy Simulator" icon={<Activity size={18} />}>
            <div className="assistant-row">
              <input
                value={simulatorInput}
                onChange={(event) => setSimulatorInput(event.target.value)}
                aria-label="Shell command to simulate"
              />
              <button onClick={runSimulator}>Run</button>
            </div>
            {simulatorResult ? (
              <div className="simulation-result">
                <div className="decision-row">
                  <span>Effective</span>
                  <strong className={`decision ${simulatorResult.decision.decision}`}>{simulatorResult.decision.decision}</strong>
                </div>
                <div className="decision-row">
                  <span>Shell</span>
                  <strong className={`decision ${simulatorResult.shellDecision.decision}`}>{simulatorResult.shellDecision.decision}</strong>
                </div>
                {(simulatorResult.networkDecisions ?? []).map((item) => (
                  <div className="decision-row" key={item.domain}>
                    <span>{item.domain}</span>
                    <strong className={`decision ${item.decision.decision}`}>{item.decision.decision}</strong>
                  </div>
                ))}
                <pre className="policy simulation-explanation">{simulatorResult.explanation.join("\n")}</pre>
              </div>
            ) : (
              <div className="empty-state">No simulation run yet</div>
            )}
            <div className="status status-neutral">{simulatorStatus}</div>
          </Panel>

          <Panel title="Audit Log" icon={<History size={18} />}>
            <div className="filter-row" aria-label="Audit filters">
              <input
                value={auditActorFilter}
                onChange={(event) => setAuditActorFilter(event.target.value)}
                placeholder="Actor"
                aria-label="Filter audit actor"
              />
              <input
                value={auditActionFilter}
                onChange={(event) => setAuditActionFilter(event.target.value)}
                placeholder="Action"
                aria-label="Filter audit action"
              />
              <select
                value={auditDecisionFilter}
                onChange={(event) => setAuditDecisionFilter(event.target.value as AuditDecisionFilter)}
                aria-label="Filter audit decision"
              >
                <option value="all">All decisions</option>
                <option value="allow">Allow</option>
                <option value="ask">Ask</option>
                <option value="deny">Deny</option>
              </select>
              <button className="text-button" onClick={refreshAudit}><RefreshCw size={15} />Refresh</button>
            </div>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Decision</th>
                  <th>Risk</th>
                  <th>Subject</th>
                </tr>
              </thead>
              <tbody>
                {auditEvents.map((item) => (
                  <tr key={item.id}>
                    <td>{formatAuditTime(item.timestamp)}</td>
                    <td>{item.actor}</td>
                    <td>{item.action}</td>
                    <td><span className={`decision ${item.decision}`}>{item.decision}</span></td>
                    <td>{item.risk}</td>
                    <td>{item.subject}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          <Panel title="MCP & Skill Controls" icon={<Plug size={18} />}>
            <div className="control-list">
              <Control name="github/list_pull_requests" value="allow" />
              <Control name="github/create_pull_request" value="ask" />
              <Control name="github/merge_pull_request" value="deny" />
              <Control name="skill/deploy-production" value="deny" />
            </div>
          </Panel>

          <Panel title="Team & Exports" icon={<Shield size={18} />}>
            <div className="export-panel">
              <div>
                <span>Policy bundle digest</span>
                <code>{bundleDigest}</code>
              </div>
              <div>
                <span>Signature status</span>
                <strong className={`signature-status signature-${bundleSignature}`}>{bundleSignature}</strong>
              </div>
              <div className="export-actions">
                <a href={`${daemonBase}/audit/export?format=csv&limit=1000`}>Audit CSV</a>
                <a href={`${daemonBase}/audit/export?format=json&limit=1000`}>Audit JSON</a>
                <button onClick={refreshBundleDigest}>Refresh Bundle</button>
              </div>
            </div>
          </Panel>
        </section>
      </section>
    </main>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function Panel({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="panel">
      <div className="panel-title">
        {icon}
        <h2>{title}</h2>
      </div>
      {children}
    </section>
  );
}

function Control({ name, value }: { name: string; value: string }) {
  return (
    <div className="control">
      <span>{name}</span>
      <strong className={`decision ${value}`}>{value}</strong>
    </div>
  );
}

function formatAuditTime(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "--:--";
  }
  return new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function parseCommandLine(value: string) {
  const matches = value.trim().match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  return matches.map((item) => {
    if (
      (item.startsWith("\"") && item.endsWith("\"")) ||
      (item.startsWith("'") && item.endsWith("'"))
    ) {
      return item.slice(1, -1);
    }
    return item;
  });
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
