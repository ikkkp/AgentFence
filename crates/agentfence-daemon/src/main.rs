use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::{env, fs};

use agentfence_approval::{
    ApprovalCreate, ApprovalQueue, ApprovalRequest, ApprovalResolve, ApprovalStatus,
};
use agentfence_audit::{AuditExportFormat, AuditStore};
use agentfence_mcp::McpAccessRequest;
use agentfence_policy::{
    Decision, DecisionResult, FilesystemRequest, NetworkRequest, Policy, PolicyBundle,
    ShellRequest, SkillRequest, create_policy_bundle, discover_policy, evaluate_filesystem,
    evaluate_network, evaluate_shell, evaluate_skill, load_policy, propose_policy_patch,
    save_policy, verify_policy_bundle,
};
use agentfence_shell::{classify_command, extract_network_domains};
use anyhow::{Context, Result};
use axum::extract::{Path as AxumPath, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

#[derive(Debug, Parser)]
#[command(name = "agentfenced")]
#[command(about = "AgentFence local daemon")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:37421")]
    listen: SocketAddr,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long, default_value = ".agentfence/audit.sqlite")]
    audit: PathBuf,
}

struct AppState {
    policy_path: PathBuf,
    audit_path: PathBuf,
    approvals: Mutex<ApprovalQueue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShellCheckInput {
    #[serde(default = "default_actor")]
    actor: String,
    command: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ShellCheckOutput {
    request: ShellRequest,
    decision: agentfence_policy::DecisionResult,
    shell_decision: agentfence_policy::DecisionResult,
    summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    network_decisions: Vec<NetworkDecisionOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<ApprovalRequest>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkDecisionOutput {
    domain: String,
    decision: agentfence_policy::DecisionResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<ApprovalRequest>,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

#[derive(Debug, Deserialize)]
struct AuditExportQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default = "default_export_format")]
    format: String,
}

#[derive(Debug, Deserialize)]
struct ApprovalQuery {
    status: Option<ApprovalStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyAskInput {
    instruction: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyBundleQuery {
    #[serde(default = "default_bundle_name")]
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    organization: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = match args.policy {
        Some(path) => path,
        None => discover_policy(&cwd).unwrap_or_else(|_| cwd.join("agentfence.policy.json")),
    };
    let initial_policy = load_policy(&policy_path)?;

    let state = Arc::new(AppState {
        policy_path,
        audit_path: args.audit,
        approvals: Mutex::new(ApprovalQueue::new(initial_policy.approval.ttl_seconds)),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/policy", get(policy).put(policy_update))
        .route("/policy/validate", post(policy_validate))
        .route("/policy/ask", post(policy_ask))
        .route("/policy/presets", get(policy_presets))
        .route("/policy/bundle", get(policy_bundle_export))
        .route("/policy/bundle/verify", post(policy_bundle_verify))
        .route("/policy/bundle/import", post(policy_bundle_import))
        .route("/audit", get(audit))
        .route("/audit/export", get(audit_export))
        .route("/approvals", get(approvals).post(create_approval))
        .route("/approvals/:id", get(approval))
        .route("/approvals/:id/resolve", post(resolve_approval))
        .route("/shell/check", post(shell_check))
        .route("/filesystem/check", post(filesystem_check))
        .route("/network/check", post(network_check))
        .route("/skill/check", post(skill_check))
        .route("/mcp/check", post(mcp_check))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    println!("agentfenced listening on http://{}", args.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("daemon server failed")?;
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ready",
        "service": "agentfenced",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn policy(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let raw = fs::read_to_string(&state.policy_path)
        .with_context(|| format!("failed to read policy {}", state.policy_path.display()))?;
    let value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy {}", state.policy_path.display()))?;
    Ok(Json(value))
}

async fn policy_validate(Json(input): Json<Value>) -> Json<Value> {
    match serde_json::from_value::<Policy>(input) {
        Ok(_) => Json(json!({
            "valid": true
        })),
        Err(error) => Json(json!({
            "valid": false,
            "error": error.to_string()
        })),
    }
}

async fn policy_update(
    State(state): State<Arc<AppState>>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let _: Policy = serde_json::from_value(input.clone()).context("invalid policy JSON")?;
    let raw = serde_json::to_string_pretty(&input).context("failed to serialize policy JSON")?;
    fs::write(&state.policy_path, raw)
        .with_context(|| format!("failed to write policy {}", state.policy_path.display()))?;
    Ok(Json(json!({
        "saved": true,
        "policy": input
    })))
}

async fn policy_ask(Json(input): Json<PolicyAskInput>) -> Result<Json<Value>, ApiError> {
    let proposal = propose_policy_patch(&input.instruction);
    Ok(Json(serde_json::to_value(proposal)?))
}

async fn policy_presets() -> Json<Value> {
    Json(json!([
        "read-only",
        "developer",
        "strict",
        "trusted-project",
        "ci-like"
    ]))
}

async fn policy_bundle_export(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PolicyBundleQuery>,
) -> Result<Json<Value>, ApiError> {
    let policy = load_policy(&state.policy_path)?;
    let bundle = create_policy_bundle(query.name, query.description, query.organization, policy)?;
    Ok(Json(serde_json::to_value(bundle)?))
}

async fn policy_bundle_verify(Json(bundle): Json<PolicyBundle>) -> Result<Json<Value>, ApiError> {
    let verification = verify_policy_bundle(&bundle)?;
    Ok(Json(serde_json::to_value(verification)?))
}

async fn policy_bundle_import(
    State(state): State<Arc<AppState>>,
    Json(bundle): Json<PolicyBundle>,
) -> Result<Json<Value>, ApiError> {
    let verification = verify_policy_bundle(&bundle)?;
    if !verification.valid {
        return Err(ApiError(anyhow::anyhow!(
            "policy bundle digest verification failed"
        )));
    }
    save_policy(&state.policy_path, &bundle.policy)?;
    Ok(Json(json!({
        "imported": true,
        "verification": verification
    })))
}

async fn audit(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let store = AuditStore::open(&state.audit_path)?;
    let events = store.list_recent(query.limit)?;
    Ok(Json(serde_json::to_value(events)?))
}

async fn audit_export(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditExportQuery>,
) -> Result<Response, ApiError> {
    let store = AuditStore::open(&state.audit_path)?;
    let format = parse_audit_format(&query.format)?;
    let exported = store.export(query.limit, format)?;
    let content_type = match format {
        AuditExportFormat::Json => "application/json",
        AuditExportFormat::Csv => "text/csv; charset=utf-8",
    };
    Ok(([(axum::http::header::CONTENT_TYPE, content_type)], exported).into_response())
}

async fn shell_check(
    State(state): State<Arc<AppState>>,
    Json(input): Json<ShellCheckInput>,
) -> Result<Json<ShellCheckOutput>, ApiError> {
    let policy = load_policy(&state.policy_path)?;
    let cwd = input.cwd.unwrap_or_else(|| {
        env::current_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    });
    let command = classify_command(&input.command);
    let request = ShellRequest {
        actor: input.actor,
        command: command.command_line,
        args: input.command,
        cwd,
        risk: command.risk,
    };
    let shell_decision = evaluate_shell(&policy, &request);
    let approval = enqueue_if_ask(
        &state,
        input_metadata("shell", &request.args),
        request.actor.clone(),
        "shell.exec".to_string(),
        request.command.clone(),
        &shell_decision,
    )
    .await;
    let mut network_decisions = Vec::new();
    for domain in extract_network_domains(&request.args) {
        let decision = evaluate_network(
            &policy,
            &NetworkRequest {
                domain: domain.clone(),
            },
        );
        let approval = enqueue_if_ask(
            &state,
            json!({
                "kind": "network",
                "domain": &domain,
                "args": &request.args
            }),
            request.actor.clone(),
            "network.request".to_string(),
            domain.clone(),
            &decision,
        )
        .await;
        network_decisions.push(NetworkDecisionOutput {
            domain,
            decision,
            approval,
        });
    }
    let decision = effective_shell_decision(&shell_decision, &network_decisions);

    Ok(Json(ShellCheckOutput {
        request,
        decision,
        shell_decision,
        summary: command.summary,
        network_decisions,
        approval,
    }))
}

async fn mcp_check(
    State(state): State<Arc<AppState>>,
    Json(input): Json<McpAccessRequest>,
) -> Result<Json<Value>, ApiError> {
    let policy = load_policy(&state.policy_path)?;
    let output = agentfence_mcp::decide(&policy, input);
    let approval = enqueue_if_ask(
        &state,
        output.request.arguments.clone(),
        "agent".to_string(),
        format!("mcp.{}", output.request.kind),
        format!("{}/{}", output.request.server, output.request.name),
        &output.decision,
    )
    .await;
    Ok(Json(json!({
        "request": output.request,
        "decision": output.decision,
        "approval": approval
    })))
}

async fn filesystem_check(
    State(state): State<Arc<AppState>>,
    Json(input): Json<FilesystemRequest>,
) -> Result<Json<Value>, ApiError> {
    let policy = load_policy(&state.policy_path)?;
    let decision = evaluate_filesystem(&policy, &input);
    let approval = enqueue_if_ask(
        &state,
        Value::Null,
        "agent".to_string(),
        format!("filesystem.{}", input.operation),
        input.path.clone(),
        &decision,
    )
    .await;
    Ok(Json(json!({
        "request": input,
        "decision": decision,
        "approval": approval
    })))
}

async fn network_check(
    State(state): State<Arc<AppState>>,
    Json(input): Json<NetworkRequest>,
) -> Result<Json<Value>, ApiError> {
    let policy = load_policy(&state.policy_path)?;
    let decision = evaluate_network(&policy, &input);
    let approval = enqueue_if_ask(
        &state,
        Value::Null,
        "agent".to_string(),
        "network.request".to_string(),
        input.domain.clone(),
        &decision,
    )
    .await;
    Ok(Json(json!({
        "request": input,
        "decision": decision,
        "approval": approval
    })))
}

async fn skill_check(
    State(state): State<Arc<AppState>>,
    Json(input): Json<SkillRequest>,
) -> Result<Json<Value>, ApiError> {
    let policy = load_policy(&state.policy_path)?;
    let decision = evaluate_skill(&policy, &input);
    let approval = enqueue_if_ask(
        &state,
        Value::Null,
        "agent".to_string(),
        "skill.use".to_string(),
        input.skill.clone(),
        &decision,
    )
    .await;
    Ok(Json(json!({
        "request": input,
        "decision": decision,
        "approval": approval
    })))
}

async fn approvals(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ApprovalQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut approvals = state.approvals.lock().await;
    Ok(Json(serde_json::to_value(approvals.list(query.status))?))
}

async fn approval(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let mut approvals = state.approvals.lock().await;
    let Some(approval) = approvals.get(&id) else {
        return Err(ApiError::not_found(format!(
            "approval request {id} was not found"
        )));
    };
    Ok(Json(serde_json::to_value(approval)?))
}

async fn create_approval(
    State(state): State<Arc<AppState>>,
    Json(input): Json<ApprovalCreate>,
) -> Result<Json<Value>, ApiError> {
    let mut approvals = state.approvals.lock().await;
    let approval = approvals.enqueue(input);
    Ok(Json(serde_json::to_value(approval)?))
}

async fn resolve_approval(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<ApprovalResolve>,
) -> Result<Json<Value>, ApiError> {
    let mut approvals = state.approvals.lock().await;
    let Some(approval) = approvals.resolve(&id, input) else {
        return Err(ApiError::not_found(format!(
            "approval request {id} was not found"
        )));
    };
    Ok(Json(serde_json::to_value(approval)?))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn default_actor() -> String {
    "codex".to_string()
}

fn default_limit() -> usize {
    50
}

fn default_export_format() -> String {
    "json".to_string()
}

fn default_bundle_name() -> String {
    "AgentFence Policy Bundle".to_string()
}

fn parse_audit_format(value: &str) -> Result<AuditExportFormat, ApiError> {
    match value.to_ascii_lowercase().as_str() {
        "json" => Ok(AuditExportFormat::Json),
        "csv" => Ok(AuditExportFormat::Csv),
        _ => Err(ApiError(anyhow::anyhow!(
            "unknown audit export format {value}"
        ))),
    }
}

fn input_metadata(kind: &str, args: &[String]) -> Value {
    json!({
        "kind": kind,
        "args": args
    })
}

async fn enqueue_if_ask(
    state: &Arc<AppState>,
    metadata: Value,
    actor: String,
    action: String,
    subject: String,
    decision: &DecisionResult,
) -> Option<ApprovalRequest> {
    if decision.decision != Decision::Ask {
        return None;
    }

    let mut approvals = state.approvals.lock().await;
    Some(approvals.enqueue(ApprovalCreate {
        actor,
        action,
        subject,
        decision: decision.clone(),
        metadata,
    }))
}

fn effective_shell_decision(
    shell: &DecisionResult,
    network: &[NetworkDecisionOutput],
) -> DecisionResult {
    if shell.decision == Decision::Deny {
        return shell.clone();
    }

    if let Some(output) = network
        .iter()
        .find(|output| output.decision.decision == Decision::Deny)
    {
        let mut decision = output.decision.clone();
        decision.reason = format!("network {}: {}", output.domain, decision.reason);
        return decision;
    }

    if shell.decision == Decision::Ask {
        return shell.clone();
    }

    if let Some(output) = network
        .iter()
        .find(|output| output.decision.decision == Decision::Ask)
    {
        let mut decision = output.decision.clone();
        decision.reason = format!("network {}: {}", output.domain, decision.reason);
        return decision;
    }

    shell.clone()
}

#[derive(Debug)]
struct ApiError(anyhow::Error);

impl ApiError {
    fn not_found(message: String) -> Self {
        Self(anyhow::anyhow!(message))
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self(error.into())
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = if self.0.to_string().contains("was not found") {
            axum::http::StatusCode::NOT_FOUND
        } else {
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        };
        let body = Json(json!({
            "error": self.0.to_string()
        }));
        (status, body).into_response()
    }
}
