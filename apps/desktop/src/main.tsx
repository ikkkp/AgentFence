import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import type {
  ApprovalRequest,
  AuditEvent,
  JsonPatchOperation,
  PolicySuggestion,
  PolicySuggestionReport,
  ShellSimulationOutput
} from "@agentfence/types";
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
  SlidersHorizontal,
  X
} from "lucide-react";
import "./styles.css";

const DEFAULT_DAEMON_BASE = "http://127.0.0.1:37421";
type AuditDecisionFilter = "all" | "allow" | "deny" | "ask";
type PolicyDiff = { hasChanges: boolean; summary: string; text: string };
type DiffOperation = { type: "same" | "add" | "remove"; text: string };

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
  const [daemonBase, setDaemonBase] = useState(DEFAULT_DAEMON_BASE);
  const [daemonBaseDraft, setDaemonBaseDraft] = useState(DEFAULT_DAEMON_BASE);
  const [daemon, setDaemon] = useState<"checking" | "ready" | "offline">("checking");
  const [approvals, setApprovals] = useState<ApprovalRequest[]>(fallbackApprovals);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>(fallbackAudit);
  const [auditActorFilter, setAuditActorFilter] = useState("");
  const [auditActionFilter, setAuditActionFilter] = useState("");
  const [auditDecisionFilter, setAuditDecisionFilter] = useState<AuditDecisionFilter>("all");
  const [policyInstruction, setPolicyInstruction] = useState("allow tests but ask before dependency installs");
  const [policyProposal, setPolicyProposal] = useState(policyPreview);
  const [policyText, setPolicyText] = useState(policyPreview);
  const [savedPolicyText, setSavedPolicyText] = useState(policyPreview);
  const [policyStatus, setPolicyStatus] = useState("Sample policy loaded");
  const [policyStatusKind, setPolicyStatusKind] = useState<"neutral" | "valid" | "invalid">("neutral");
  const [policyDirty, setPolicyDirty] = useState(false);
  const [policySuggestions, setPolicySuggestions] = useState<PolicySuggestion[]>([]);
  const [suggestionStatus, setSuggestionStatus] = useState("Suggestions not loaded");
  const [simulatorInput, setSimulatorInput] = useState("git status https://transfer.sh/file");
  const [simulatorResult, setSimulatorResult] = useState<ShellSimulationOutput | null>(null);
  const [simulatorStatus, setSimulatorStatus] = useState("Ready");
  const [bundleDigest, setBundleDigest] = useState("not loaded");
  const [bundleSignature, setBundleSignature] = useState("not checked");
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission | "unsupported">("unsupported");
  const policyDiff = useMemo(
    () => buildPolicyDiff(savedPolicyText, policyText),
    [savedPolicyText, policyText]
  );

  useEffect(() => {
    const controller = new AbortController();
    setDaemon("checking");
    fetch(`${daemonBase}/health`, { signal: controller.signal })
      .then((response) => {
        setDaemon(response.ok ? "ready" : "offline");
      })
      .catch(() => setDaemon("offline"));
    return () => controller.abort();
  }, [daemonBase]);

  useEffect(() => {
    if ("Notification" in window) {
      setNotificationPermission(Notification.permission);
    }
    refreshApprovals();
    refreshPolicy();
    refreshPolicySuggestions();
    refreshBundleDigest();
    const timer = window.setInterval(() => {
      refreshApprovals();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [notificationPermission, daemonBase]);

  useEffect(() => {
    refreshAudit();
    const timer = window.setInterval(refreshAudit, 5000);
    return () => window.clearInterval(timer);
  }, [auditActorFilter, auditActionFilter, auditDecisionFilter, daemonBase]);

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
      const formatted = JSON.stringify(policy, null, 2);
      setPolicyText(formatted);
      setSavedPolicyText(formatted);
      setPolicyStatus("Policy loaded from daemon");
      setPolicyStatusKind("valid");
      setPolicyDirty(false);
    } catch {
      setPolicyText(policyPreview);
      setSavedPolicyText(policyPreview);
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

  async function refreshPolicySuggestions() {
    setSuggestionStatus("Scanning audit");
    try {
      const params = new URLSearchParams({ threshold: "3", limit: "1000" });
      const response = await fetch(`${daemonBase}/policy/suggestions?${params.toString()}`);
      if (!response.ok) {
        setSuggestionStatus("Suggestion scan failed");
        return;
      }
      const report = (await response.json()) as PolicySuggestionReport;
      setPolicySuggestions(report.suggestions ?? []);
      setSuggestionStatus(
        report.suggestions.length > 0
          ? `${report.suggestions.length} suggestion${report.suggestions.length === 1 ? "" : "s"}`
          : "No suggestions"
      );
    } catch {
      setPolicySuggestions([]);
      setSuggestionStatus("Daemon offline");
    }
  }

  function applySuggestion(suggestion: PolicySuggestion) {
    try {
      const parsed = JSON.parse(policyText);
      const patched = applyJsonPatch(parsed, suggestion.proposal.operations);
      const formatted = JSON.stringify(patched, null, 2);
      setPolicyText(formatted);
      setPolicyDirty(formatted !== savedPolicyText);
      setPolicyProposal(JSON.stringify(suggestion.proposal, null, 2));
      setPolicyStatus(`Applied suggestion: ${suggestion.title}`);
      setPolicyStatusKind("neutral");
    } catch (error) {
      setPolicyStatus(error instanceof Error ? error.message : "Suggestion patch failed");
      setPolicyStatusKind("invalid");
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
    const saved = JSON.stringify(parsed, null, 2);
    setPolicyText(saved);
    setSavedPolicyText(saved);
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

  async function sendTestNotification() {
    if (!("Notification" in window)) {
      setNotificationPermission("unsupported");
      return;
    }

    let permission = Notification.permission;
    if (permission === "default") {
      permission = await Notification.requestPermission();
      setNotificationPermission(permission);
    }
    if (permission === "granted") {
      new Notification("AgentFence notifications ready", {
        body: "Approval alerts will appear here."
      });
    }
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

  function applyDaemonBase() {
    const next = normalizeDaemonBase(daemonBaseDraft);
    setDaemonBaseDraft(next);
    setDaemonBase(next);
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
          <a><SlidersHorizontal size={18} />Settings</a>
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
            <span className={`daemon daemon-${daemon}`}>Daemon {daemon} - {daemonBase}</span>
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
            <div className="suggestion-toolbar">
              <span>Audit suggestions</span>
              <strong>{suggestionStatus}</strong>
              <button className="text-button" onClick={refreshPolicySuggestions}>
                <RefreshCw size={15} />Scan
              </button>
            </div>
            {policySuggestions.length > 0 && (
              <div className="suggestion-list">
                {policySuggestions.map((suggestion) => (
                  <article className="suggestion-item" key={suggestion.id}>
                    <div>
                      <div className="suggestion-heading">
                        <strong>{suggestion.title}</strong>
                        <span>{suggestion.eventCount}x</span>
                      </div>
                      <code>{suggestion.subject}</code>
                      <p>{suggestion.description}</p>
                    </div>
                    <div className="suggestion-actions">
                      <button
                        className="text-button"
                        onClick={() => setPolicyProposal(JSON.stringify(suggestion.proposal, null, 2))}
                      >
                        <FileJson size={15} />Preview
                      </button>
                      <button className="text-button primary" onClick={() => applySuggestion(suggestion)}>
                        <Check size={15} />Apply
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            )}
            <div className="policy-toolbar">
              <button className="text-button" onClick={refreshPolicy}><RefreshCw size={15} />Reload</button>
              <button className="text-button" onClick={validatePolicy}><CheckCircle2 size={15} />Validate</button>
              <button className="text-button primary" onClick={savePolicy} disabled={!policyDirty}><Save size={15} />Save</button>
            </div>
            <textarea
              className="policy-editor"
              value={policyText}
              onChange={(event) => {
                const nextPolicyText = event.target.value;
                const changed = nextPolicyText !== savedPolicyText;
                setPolicyText(nextPolicyText);
                setPolicyDirty(changed);
                setPolicyStatus(changed ? "Policy has unsaved changes" : "Policy matches loaded version");
                setPolicyStatusKind("neutral");
              }}
              aria-label="Policy JSON"
              spellCheck={false}
            />
            <div className="diff-toolbar">
              <span>Diff preview</span>
              <strong>{policyDiff.summary}</strong>
            </div>
            <pre className={`policy policy-diff ${policyDiff.hasChanges ? "" : "policy-diff-empty"}`}>{policyDiff.text}</pre>
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

          <Panel title="Settings" icon={<SlidersHorizontal size={18} />}>
            <div className="settings-panel">
              <label className="setting-field">
                <span>Daemon endpoint</span>
                <input
                  value={daemonBaseDraft}
                  onChange={(event) => setDaemonBaseDraft(event.target.value)}
                  aria-label="Daemon endpoint"
                />
              </label>
              <div className="setting-actions">
                <button className="text-button primary" onClick={applyDaemonBase}>Apply</button>
                <button
                  className="text-button"
                  onClick={() => {
                    setDaemonBaseDraft(DEFAULT_DAEMON_BASE);
                    setDaemonBase(DEFAULT_DAEMON_BASE);
                  }}
                >
                  Reset
                </button>
                <button className="text-button" onClick={() => {
                  refreshApprovals();
                  refreshAudit();
                  refreshPolicy();
                  refreshPolicySuggestions();
                  refreshBundleDigest();
                }}>
                  <RefreshCw size={15} />Refresh
                </button>
              </div>
              <div className="notification-settings">
                <div>
                  <span>Notification permission</span>
                  <strong>{notificationPermission}</strong>
                </div>
                <button
                  className="text-button"
                  onClick={sendTestNotification}
                  disabled={notificationPermission === "unsupported"}
                >
                  <Bell size={15} />Test alert
                </button>
              </div>
              <div className="settings-grid">
                <div>
                  <span>Status</span>
                  <strong className={`daemon daemon-${daemon}`}>{daemon}</strong>
                </div>
                <div>
                  <span>Audit export</span>
                  <code>{`${daemonBase}/audit/export`}</code>
                </div>
                <div>
                  <span>Policy bundle</span>
                  <code>{`${daemonBase}/policy/bundle`}</code>
                </div>
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

function normalizeDaemonBase(value: string) {
  const trimmed = value.trim().replace(/\/+$/, "");
  return trimmed || DEFAULT_DAEMON_BASE;
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

function applyJsonPatch(root: unknown, operations: JsonPatchOperation[]) {
  let next = cloneJson(root);
  for (const operation of operations) {
    if (operation.op === "add") {
      next = jsonPointerAdd(next, operation.path, cloneJson(operation.value));
    } else if (operation.op === "replace") {
      next = jsonPointerReplace(next, operation.path, cloneJson(operation.value));
    } else if (operation.op === "test") {
      jsonPointerTest(next, operation.path, operation.value);
    } else {
      throw new Error(`Unsupported JSON Patch operation ${operation.op}`);
    }
  }
  return next;
}

function jsonPointerAdd(root: unknown, path: string, value: unknown) {
  const tokens = jsonPointerTokens(path);
  if (tokens.length === 0) {
    return value;
  }
  const { parent, key } = jsonPointerParent(root, tokens);
  if (Array.isArray(parent)) {
    if (key === "-") {
      parent.push(value);
      return root;
    }
    const index = Number.parseInt(key, 10);
    if (!Number.isInteger(index) || index < 0 || index > parent.length) {
      throw new Error(`Invalid JSON pointer array index ${key}`);
    }
    parent.splice(index, 0, value);
    return root;
  }
  parent[key] = value;
  return root;
}

function jsonPointerReplace(root: unknown, path: string, value: unknown) {
  const tokens = jsonPointerTokens(path);
  if (tokens.length === 0) {
    return value;
  }
  const { parent, key } = jsonPointerParent(root, tokens);
  if (Array.isArray(parent)) {
    const index = Number.parseInt(key, 10);
    if (!Number.isInteger(index) || index < 0 || index >= parent.length) {
      throw new Error(`JSON pointer array index ${key} was not found`);
    }
    parent[index] = value;
    return root;
  }
  if (!(key in parent)) {
    throw new Error(`JSON pointer object key ${key} was not found`);
  }
  parent[key] = value;
  return root;
}

function jsonPointerTest(root: unknown, path: string, expected: unknown) {
  const actual = jsonPointerGet(root, jsonPointerTokens(path));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`JSON pointer test failed at ${path}`);
  }
}

function jsonPointerGet(root: unknown, tokens: string[]) {
  let current = root;
  for (const token of tokens) {
    if (Array.isArray(current)) {
      const index = Number.parseInt(token, 10);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) {
        throw new Error(`JSON pointer array index ${token} was not found`);
      }
      current = current[index];
    } else if (isRecord(current) && token in current) {
      current = current[token];
    } else {
      throw new Error(`JSON pointer object key ${token} was not found`);
    }
  }
  return current;
}

function jsonPointerParent(root: unknown, tokens: string[]) {
  const parent = jsonPointerGet(root, tokens.slice(0, -1));
  if (!Array.isArray(parent) && !isRecord(parent)) {
    throw new Error("JSON pointer parent is not an array or object");
  }
  return {
    parent,
    key: tokens[tokens.length - 1]
  };
}

function jsonPointerTokens(path: string) {
  if (path === "") {
    return [];
  }
  if (!path.startsWith("/")) {
    throw new Error(`JSON pointer must start with /: ${path}`);
  }
  return path
    .split("/")
    .slice(1)
    .map((token) => token.replace(/~1/g, "/").replace(/~0/g, "~"));
}

function cloneJson(value: unknown) {
  return JSON.parse(JSON.stringify(value)) as unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function buildPolicyDiff(before: string, after: string): PolicyDiff {
  if (before === after) {
    return {
      hasChanges: false,
      summary: "No changes",
      text: "No policy changes."
    };
  }

  const beforeLines = before.split(/\r?\n/);
  const afterLines = after.split(/\r?\n/);
  const operations = diffLines(beforeLines, afterLines);
  const added = operations.filter((operation) => operation.type === "add").length;
  const removed = operations.filter((operation) => operation.type === "remove").length;

  return {
    hasChanges: true,
    summary: `+${added} / -${removed}`,
    text: renderDiff(operations)
  };
}

function diffLines(before: string[], after: string[]): DiffOperation[] {
  const table = Array.from({ length: before.length + 1 }, () => Array(after.length + 1).fill(0));

  for (let beforeIndex = before.length - 1; beforeIndex >= 0; beforeIndex -= 1) {
    for (let afterIndex = after.length - 1; afterIndex >= 0; afterIndex -= 1) {
      table[beforeIndex][afterIndex] = before[beforeIndex] === after[afterIndex]
        ? table[beforeIndex + 1][afterIndex + 1] + 1
        : Math.max(table[beforeIndex + 1][afterIndex], table[beforeIndex][afterIndex + 1]);
    }
  }

  const operations: DiffOperation[] = [];
  let beforeIndex = 0;
  let afterIndex = 0;

  while (beforeIndex < before.length && afterIndex < after.length) {
    if (before[beforeIndex] === after[afterIndex]) {
      operations.push({ type: "same", text: before[beforeIndex] });
      beforeIndex += 1;
      afterIndex += 1;
    } else if (table[beforeIndex + 1][afterIndex] >= table[beforeIndex][afterIndex + 1]) {
      operations.push({ type: "remove", text: before[beforeIndex] });
      beforeIndex += 1;
    } else {
      operations.push({ type: "add", text: after[afterIndex] });
      afterIndex += 1;
    }
  }

  while (beforeIndex < before.length) {
    operations.push({ type: "remove", text: before[beforeIndex] });
    beforeIndex += 1;
  }

  while (afterIndex < after.length) {
    operations.push({ type: "add", text: after[afterIndex] });
    afterIndex += 1;
  }

  return operations;
}

function renderDiff(operations: DiffOperation[]) {
  const output: string[] = [];
  let sameRun: string[] = [];

  const flushSameRun = () => {
    if (sameRun.length === 0) {
      return;
    }
    if (sameRun.length <= 4) {
      output.push(...sameRun.map((line) => `  ${line}`));
    } else {
      output.push(...sameRun.slice(0, 2).map((line) => `  ${line}`));
      output.push(`  ... ${sameRun.length - 4} unchanged lines ...`);
      output.push(...sameRun.slice(-2).map((line) => `  ${line}`));
    }
    sameRun = [];
  };

  for (const operation of operations) {
    if (operation.type === "same") {
      sameRun.push(operation.text);
      continue;
    }
    flushSameRun();
    output.push(`${operation.type === "add" ? "+" : "-"} ${operation.text}`);
  }

  flushSameRun();
  return output.join("\n");
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
