use agentfence_policy::{Decision, DecisionResult, Policy, evaluate_mcp};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};

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
}

pub fn decide(policy: &Policy, request: McpAccessRequest) -> McpAccessDecision {
    let decision = evaluate_mcp(policy, &request.server, &request.kind, &request.name);
    McpAccessDecision { request, decision }
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

    use agentfence_policy::{Decision, McpServerPolicy, Policy};

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
}
