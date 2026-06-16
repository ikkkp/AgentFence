export type Decision =
  | "allow"
  | "deny"
  | "ask"
  | "allow_once"
  | "allow_for_session"
  | "allow_with_constraints";

export type Risk = "low" | "medium" | "high" | "critical";

export interface ShellRule {
  id: string;
  description?: string;
  match?: {
    commands?: string[];
    patterns?: string[];
    risks?: Risk[];
  };
  decision: Decision;
  reason?: string;
}

export interface AgentFencePolicy {
  version: string;
  project?: string;
  defaultDecision?: Decision;
  actors?: Record<string, { trustLevel?: string }>;
  shell?: {
    rules?: ShellRule[];
  };
  filesystem?: {
    allowRoots?: string[];
    denyPaths?: string[];
    write?: {
      decision?: Decision;
      allowExtensions?: string[];
    };
  };
  network?: {
    defaultDecision?: Decision;
    allowDomains?: string[];
    denyDomains?: string[];
  };
  mcp?: {
    servers?: Record<
      string,
      {
        enabled?: boolean;
        decision?: Decision;
        tools?: Record<string, Decision>;
        resources?: Record<string, Decision>;
        prompts?: Record<string, Decision>;
      }
    >;
  };
  skills?: {
    defaultDecision?: Decision;
    allow?: string[];
    deny?: string[];
  };
  approval?: {
    ttlSeconds?: number;
    rememberChoices?: boolean;
    requireReasonForHighRisk?: boolean;
  };
  audit?: {
    enabled?: boolean;
    store?: string;
  };
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  subject: string;
  decision: string;
  risk: string;
  reason: string;
  matchedRule?: string;
  cwd?: string;
  metadata?: unknown;
}

export interface DecisionResult {
  decision: Decision;
  reason: string;
  matchedRule?: string | null;
  risk: Risk;
}

export interface ShellRequest {
  actor: string;
  command: string;
  args?: string[];
  cwd: string;
  risk: Risk;
}

export type ApprovalStatus = "pending" | "allowed" | "denied" | "expired";

export interface ApprovalRequest {
  id: string;
  createdAt?: string;
  expiresAt?: string;
  actor: string;
  action: string;
  subject: string;
  risk: Risk;
  reason: string;
  cwd?: string;
  matchedRule?: string;
  status?: ApprovalStatus;
  metadata?: unknown;
  resolution?: {
    decision: "allowed" | "denied";
    responder: string;
    reason?: string;
    resolvedAt: string;
  } | null;
}

export interface ShellNetworkDecision {
  domain: string;
  decision: DecisionResult;
  approval?: ApprovalRequest | null;
}

export interface ShellCheckOutput {
  request: ShellRequest;
  decision: DecisionResult;
  shellDecision: DecisionResult;
  summary: string;
  networkDecisions?: ShellNetworkDecision[];
  approval?: ApprovalRequest | null;
}

export interface ShellSimulationNetworkDecision {
  domain: string;
  decision: DecisionResult;
}

export interface ShellSimulationOutput {
  request: ShellRequest;
  decision: DecisionResult;
  shellDecision: DecisionResult;
  summary: string;
  networkDecisions?: ShellSimulationNetworkDecision[];
  explanation: string[];
}
