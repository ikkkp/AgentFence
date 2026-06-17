use agentfence_policy::{Decision, DecisionResult, Policy, RateLimitPolicy, Risk, evaluate_mcp};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Read, Write};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAccessRequest {
    pub server: String,
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAccessDecision {
    pub request: McpAccessRequest,
    pub decision: DecisionResult,
    #[serde(default, skip_serializing_if = "McpArgumentInspection::is_clean")]
    pub argument_inspection: McpArgumentInspection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpArgumentInspection {
    pub risk: Risk,
    pub findings: Vec<String>,
}

impl Default for McpArgumentInspection {
    fn default() -> Self {
        Self {
            risk: Risk::Low,
            findings: Vec::new(),
        }
    }
}

impl McpArgumentInspection {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

pub fn decide(policy: &Policy, request: McpAccessRequest) -> McpAccessDecision {
    let mut decision = evaluate_mcp(policy, &request.server, &request.kind, &request.name);
    let inspection = inspect_arguments(&request);
    decision.risk = decision.risk.max(inspection.risk);

    if !inspection.is_clean() {
        let summary = inspection.findings.join("; ");
        if matches!(
            decision.decision,
            Decision::Allow
                | Decision::AllowOnce
                | Decision::AllowForSession
                | Decision::AllowWithConstraints
        ) && inspection.risk >= Risk::High
        {
            decision.decision = Decision::Ask;
            decision.reason = format!(
                "MCP arguments require review before forwarding: {summary}; base decision was allow"
            );
            decision.matched_rule = Some("mcp.argumentInspection".to_string());
        } else {
            decision.reason = format!("{}; MCP argument inspection: {summary}", decision.reason);
        }
    }

    McpAccessDecision {
        request,
        decision,
        argument_inspection: inspection,
    }
}

pub fn inspect_arguments(request: &McpAccessRequest) -> McpArgumentInspection {
    let mut inspection = McpArgumentInspection {
        risk: Risk::Low,
        findings: Vec::new(),
    };

    inspect_surface_name(request, &mut inspection);
    inspect_value("$", &request.arguments, &mut inspection);

    inspection
}

fn inspect_surface_name(request: &McpAccessRequest, inspection: &mut McpArgumentInspection) {
    let name = request.name.to_ascii_lowercase();
    if contains_any(
        &name,
        &[
            "secret",
            "credential",
            "token",
            "private_key",
            "private-key",
        ],
    ) {
        push_finding(
            inspection,
            Risk::Critical,
            format!(
                "{} name references secret or credential material",
                request.kind
            ),
        );
    }

    if contains_any(
        &name,
        &[
            "delete", "destroy", "merge", "deploy", "publish", "exec", "shell", "command",
        ],
    ) {
        push_finding(
            inspection,
            Risk::High,
            format!("{} name suggests high-impact operation", request.kind),
        );
    }
}

fn inspect_value(path: &str, value: &Value, inspection: &mut McpArgumentInspection) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                inspect_key(&child_path, key, inspection);
                inspect_value(&child_path, child, inspection);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                inspect_value(&format!("{path}[{index}]"), child, inspection);
            }
        }
        Value::String(value) => inspect_string(path, value, inspection),
        _ => {}
    }
}

fn inspect_key(path: &str, key: &str, inspection: &mut McpArgumentInspection) {
    let lower = key.to_ascii_lowercase();
    if contains_any(
        &lower,
        &[
            "token",
            "password",
            "secret",
            "api_key",
            "apikey",
            "credential",
            "private_key",
            "private-key",
        ],
    ) {
        push_finding(
            inspection,
            Risk::Critical,
            format!("{path} key suggests secret material"),
        );
    }
}

fn inspect_string(path: &str, value: &str, inspection: &mut McpArgumentInspection) {
    let lower = value.to_ascii_lowercase();

    if contains_any(
        &lower,
        &[
            "~/.ssh",
            ".ssh/",
            ".env",
            "id_rsa",
            "id_ed25519",
            "secrets.json",
            ".aws/",
            "credentials",
        ],
    ) {
        push_finding(
            inspection,
            Risk::Critical,
            format!("{path} references a sensitive path or credential file"),
        );
    }

    if looks_like_secret(value) {
        push_finding(
            inspection,
            Risk::Critical,
            format!("{path} contains a secret-looking value"),
        );
    }

    if contains_any(&lower, &["production", "prod", "release"]) {
        push_finding(
            inspection,
            Risk::High,
            format!("{path} references production or release context"),
        );
    }
}

fn looks_like_secret(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("sk-")
        || trimmed.starts_with("ghp_")
        || trimmed.starts_with("github_pat_")
        || trimmed.starts_with("AKIA")
        || trimmed.starts_with("ASIA")
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn push_finding(inspection: &mut McpArgumentInspection, risk: Risk, finding: String) {
    inspection.risk = inspection.risk.max(risk);
    if !inspection
        .findings
        .iter()
        .any(|existing| existing == &finding)
    {
        inspection.findings.push(finding);
    }
}

#[derive(Debug, Clone)]
pub struct McpRateLimiter {
    server: String,
    policy: Option<RateLimitPolicy>,
    hits: HashMap<String, VecDeque<Instant>>,
}

impl McpRateLimiter {
    pub fn for_server(policy: &Policy, server: &str) -> Self {
        let policy = policy.mcp.servers.get(server).and_then(|server_policy| {
            server_policy
                .rate_limit
                .enabled
                .then(|| server_policy.rate_limit.clone())
        });

        Self {
            server: server.to_string(),
            policy,
            hits: HashMap::new(),
        }
    }

    pub fn check(&mut self, request: &McpAccessRequest) -> Option<DecisionResult> {
        let policy = self.policy.as_ref()?;
        let window = Duration::from_secs(policy.window_seconds);
        let now = Instant::now();
        let key = format!("{}:{}", request.kind, request.name);
        let hits = self.hits.entry(key).or_default();

        while let Some(first) = hits.front() {
            if now.duration_since(*first) <= window {
                break;
            }
            hits.pop_front();
        }

        if hits.len() >= policy.max_requests as usize {
            return Some(DecisionResult {
                decision: Decision::Deny,
                reason: format!(
                    "MCP rate limit exceeded: max {} request(s) per {} second(s)",
                    policy.max_requests, policy.window_seconds
                ),
                matched_rule: Some(format!("mcp.servers.{}.rateLimit", self.server)),
                risk: Risk::High,
            });
        }

        hits.push_back(now);
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpFrameKind {
    ContentLength,
    JsonLine,
}

#[derive(Debug, Clone)]
pub struct McpFrame {
    pub kind: McpFrameKind,
    pub body: Vec<u8>,
}

pub fn inspect_client_message(server: &str, message: &Value) -> Option<McpAccessRequest> {
    let method = message.get("method")?.as_str()?;
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "tools/call" => {
            let name = params.get("name")?.as_str()?.to_string();
            Some(McpAccessRequest {
                server: server.to_string(),
                kind: "tool".to_string(),
                name,
                arguments: params.get("arguments").cloned().unwrap_or(Value::Null),
            })
        }
        "resources/read" => {
            let name = params.get("uri")?.as_str()?.to_string();
            Some(McpAccessRequest {
                server: server.to_string(),
                kind: "resource".to_string(),
                name,
                arguments: params,
            })
        }
        "prompts/get" => {
            let name = params.get("name")?.as_str()?.to_string();
            Some(McpAccessRequest {
                server: server.to_string(),
                kind: "prompt".to_string(),
                name,
                arguments: params.get("arguments").cloned().unwrap_or(Value::Null),
            })
        }
        _ => None,
    }
}

pub fn list_method(message: &Value) -> Option<&'static str> {
    match message.get("method")?.as_str()? {
        "tools/list" => Some("tools/list"),
        "resources/list" => Some("resources/list"),
        "prompts/list" => Some("prompts/list"),
        _ => None,
    }
}

pub fn message_id_key(message: &Value) -> Option<String> {
    let id = message.get("id")?;
    match id {
        Value::Null => None,
        Value::String(value) => Some(format!("s:{value}")),
        Value::Number(value) => Some(format!("n:{value}")),
        _ => serde_json::to_string(id)
            .ok()
            .map(|value| format!("j:{value}")),
    }
}

#[derive(Debug, Clone)]
pub struct ListFilterResult {
    pub response: Value,
    pub removed: usize,
}

pub fn filter_list_response(
    policy: &Policy,
    server: &str,
    method: &str,
    response: &Value,
) -> ListFilterResult {
    let Some((kind, field, name_field)) = list_shape(method) else {
        return ListFilterResult {
            response: response.clone(),
            removed: 0,
        };
    };

    let mut filtered = response.clone();
    let removed = {
        let Some(items) = filtered
            .get_mut("result")
            .and_then(|result| result.get_mut(field))
            .and_then(Value::as_array_mut)
        else {
            return ListFilterResult {
                response: filtered,
                removed: 0,
            };
        };

        let before = items.len();
        items.retain(|item| {
            let Some(name) = item.get(name_field).and_then(Value::as_str) else {
                return true;
            };
            let decision = evaluate_mcp(policy, server, kind, name);
            decision.decision != Decision::Deny
        });
        before.saturating_sub(items.len())
    };

    ListFilterResult {
        response: filtered,
        removed,
    }
}

pub fn error_response(original: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": original.get("id").cloned().unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}

pub fn read_frame<R>(reader: &mut R) -> Result<Option<McpFrame>>
where
    R: BufRead + Read,
{
    let mut first = String::new();
    let read = reader
        .read_line(&mut first)
        .context("failed to read MCP frame header")?;
    if read == 0 {
        return Ok(None);
    }

    if first.to_ascii_lowercase().starts_with("content-length:") {
        let length = parse_content_length(&first)?;
        let mut line = String::new();
        loop {
            line.clear();
            reader
                .read_line(&mut line)
                .context("failed to read MCP header separator")?;
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
        }

        let mut body = vec![0_u8; length];
        reader
            .read_exact(&mut body)
            .context("failed to read MCP content-length body")?;
        return Ok(Some(McpFrame {
            kind: McpFrameKind::ContentLength,
            body,
        }));
    }

    Ok(Some(McpFrame {
        kind: McpFrameKind::JsonLine,
        body: first.into_bytes(),
    }))
}

pub fn write_frame<W>(writer: &mut W, frame: &McpFrame) -> Result<()>
where
    W: Write,
{
    match frame.kind {
        McpFrameKind::ContentLength => {
            write!(writer, "Content-Length: {}\r\n\r\n", frame.body.len())
                .context("failed to write MCP content-length header")?;
            writer
                .write_all(&frame.body)
                .context("failed to write MCP content-length body")?;
        }
        McpFrameKind::JsonLine => {
            writer
                .write_all(&frame.body)
                .context("failed to write MCP JSON line")?;
            if !frame.body.ends_with(b"\n") {
                writer
                    .write_all(b"\n")
                    .context("failed to terminate MCP JSON line")?;
            }
        }
    }
    writer.flush().context("failed to flush MCP frame")?;
    Ok(())
}

pub fn frame_from_json(kind: McpFrameKind, value: &Value) -> Result<McpFrame> {
    Ok(McpFrame {
        kind,
        body: serde_json::to_vec(value).context("failed to encode MCP JSON response")?,
    })
}

pub fn decode_frame_json(frame: &McpFrame) -> Result<Value> {
    serde_json::from_slice(&frame.body).context("failed to parse MCP JSON message")
}

fn parse_content_length(line: &str) -> Result<usize> {
    let Some((_, value)) = line.split_once(':') else {
        bail!("invalid Content-Length header");
    };
    value
        .trim()
        .parse::<usize>()
        .context("invalid MCP Content-Length value")
}

fn list_shape(method: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match method {
        "tools/list" => Some(("tool", "tools", "name")),
        "resources/list" => Some(("resource", "resources", "uri")),
        "prompts/list" => Some(("prompt", "prompts", "name")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use agentfence_policy::{Decision, McpServerPolicy, Policy, RateLimitPolicy};

    use super::*;

    #[test]
    fn inspects_tool_call_message() {
        let message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "create_pull_request",
                "arguments": { "title": "demo" }
            }
        });

        let request = inspect_client_message("github", &message).expect("request");
        assert_eq!(request.kind, "tool");
        assert_eq!(request.name, "create_pull_request");
    }

    #[test]
    fn sensitive_allowed_tool_arguments_require_review() {
        let mut tools = BTreeMap::new();
        tools.insert("read_file".to_string(), Decision::Allow);
        let mut policy = Policy::default();
        policy.mcp.servers.insert(
            "filesystem".to_string(),
            McpServerPolicy {
                tools,
                ..McpServerPolicy::default()
            },
        );

        let decision = decide(
            &policy,
            McpAccessRequest {
                server: "filesystem".to_string(),
                kind: "tool".to_string(),
                name: "read_file".to_string(),
                arguments: json!({ "path": "~/.ssh/id_rsa" }),
            },
        );

        assert_eq!(decision.decision.decision, Decision::Ask);
        assert_eq!(decision.decision.risk, Risk::Critical);
        assert_eq!(
            decision.decision.matched_rule.as_deref(),
            Some("mcp.argumentInspection")
        );
    }

    #[test]
    fn denied_mcp_tool_stays_denied_when_arguments_are_sensitive() {
        let mut tools = BTreeMap::new();
        tools.insert("delete_file".to_string(), Decision::Deny);
        let mut policy = Policy::default();
        policy.mcp.servers.insert(
            "filesystem".to_string(),
            McpServerPolicy {
                tools,
                ..McpServerPolicy::default()
            },
        );

        let decision = decide(
            &policy,
            McpAccessRequest {
                server: "filesystem".to_string(),
                kind: "tool".to_string(),
                name: "delete_file".to_string(),
                arguments: json!({ "api_key": "sk-test" }),
            },
        );

        assert_eq!(decision.decision.decision, Decision::Deny);
        assert_eq!(decision.decision.risk, Risk::Critical);
        assert!(decision.decision.reason.contains("MCP argument inspection"));
    }

    #[test]
    fn reads_and_writes_content_length_frames() {
        let mut input = Cursor::new(b"Content-Length: 17\r\n\r\n{\"jsonrpc\":\"2.0\"}".to_vec());
        let frame = read_frame(&mut input).expect("read").expect("frame");
        assert_eq!(frame.kind, McpFrameKind::ContentLength);

        let mut output = Vec::new();
        write_frame(&mut output, &frame).expect("write");
        assert_eq!(output, b"Content-Length: 17\r\n\r\n{\"jsonrpc\":\"2.0\"}");
    }

    #[test]
    fn filters_denied_tools_from_list_response() {
        let mut tools = BTreeMap::new();
        tools.insert("merge_pull_request".to_string(), Decision::Deny);
        tools.insert("list_pull_requests".to_string(), Decision::Allow);

        let mut policy = Policy::default();
        policy.mcp.servers.insert(
            "github".to_string(),
            McpServerPolicy {
                tools,
                ..McpServerPolicy::default()
            },
        );

        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    { "name": "list_pull_requests" },
                    { "name": "merge_pull_request" }
                ]
            }
        });

        let filtered = filter_list_response(&policy, "github", "tools/list", &response);
        let tools = filtered.response["result"]["tools"]
            .as_array()
            .expect("tools");

        assert_eq!(filtered.removed, 1);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "list_pull_requests");
    }

    #[test]
    fn tracks_json_rpc_request_id_keys() {
        assert_eq!(message_id_key(&json!({ "id": 1 })).as_deref(), Some("n:1"));
        assert_eq!(
            message_id_key(&json!({ "id": "abc" })).as_deref(),
            Some("s:abc")
        );
        assert_eq!(message_id_key(&json!({ "id": null })), None);
    }

    #[test]
    fn rate_limiter_denies_after_policy_window_capacity() {
        let mut policy = Policy::default();
        policy.mcp.servers.insert(
            "github".to_string(),
            McpServerPolicy {
                rate_limit: RateLimitPolicy {
                    enabled: true,
                    max_requests: 1,
                    window_seconds: 60,
                },
                ..McpServerPolicy::default()
            },
        );
        let request = McpAccessRequest {
            server: "github".to_string(),
            kind: "tool".to_string(),
            name: "create_pull_request".to_string(),
            arguments: Value::Null,
        };

        let mut limiter = McpRateLimiter::for_server(&policy, "github");

        assert!(limiter.check(&request).is_none());
        let denied = limiter.check(&request).expect("second call should deny");

        assert_eq!(denied.decision, Decision::Deny);
        assert_eq!(
            denied.matched_rule.as_deref(),
            Some("mcp.servers.github.rateLimit")
        );
    }
}
