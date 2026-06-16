use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, MappedRows, Row, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub decision: String,
    pub risk: String,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub cwd: Option<String>,
    pub metadata: Value,
}

impl AuditEvent {
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        subject: impl Into<String>,
        decision: impl Into<String>,
        risk: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            actor: actor.into(),
            action: action.into(),
            subject: redact_secrets(&subject.into()),
            decision: decision.into(),
            risk: risk.into(),
            reason: redact_secrets(&reason.into()),
            matched_rule: None,
            cwd: None,
            metadata: Value::Object(Default::default()),
        }
    }
}

pub fn redact_secrets(input: &str) -> String {
    input
        .split_whitespace()
        .map(redact_token)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn redact_metadata(value: &Value) -> Value {
    match value {
        Value::String(value) => Value::String(redact_secrets(value)),
        Value::Array(values) => Value::Array(values.iter().map(redact_metadata).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), redact_metadata(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn redact_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    let sensitive_keys = [
        "token=",
        "password=",
        "passwd=",
        "secret=",
        "api_key=",
        "apikey=",
        "access_key=",
        "authorization:",
        "bearer ",
    ];

    for key in sensitive_keys {
        if lower.starts_with(key) || lower.contains(&format!("--{key}")) {
            if let Some(index) = token.find('=') {
                return format!("{}[REDACTED]", &token[..=index]);
            }
            if let Some(index) = token.find(':') {
                return format!("{} [REDACTED]", &token[..index]);
            }
            return "[REDACTED]".to_string();
        }
    }

    if lower.starts_with("ghp_")
        || lower.starts_with("github_pat_")
        || lower.starts_with("sk-")
        || token.starts_with("AKIA") && token.len() >= 16
    {
        return "[REDACTED_SECRET]".to_string();
    }

    token.to_string()
}

pub struct AuditStore {
    conn: Connection,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub actor: Option<String>,
    pub decision: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditExportFormat {
    Json,
    Csv,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secret_shapes() {
        let output = redact_secrets("curl token=abc123 ghp_abcdef sk-test AKIA12345678901234");
        assert_eq!(
            output,
            "curl token=[REDACTED] [REDACTED_SECRET] [REDACTED_SECRET] [REDACTED_SECRET]"
        );
    }

    #[test]
    fn audit_event_redacts_subject_and_reason() {
        let event = AuditEvent::new(
            "codex",
            "shell.exec",
            "curl password=hunter2",
            "deny",
            "high",
            "blocked token=abc",
        );

        assert_eq!(event.subject, "curl password=[REDACTED]");
        assert_eq!(event.reason, "blocked token=[REDACTED]");
    }

    #[test]
    fn metadata_redaction_walks_nested_values() {
        let metadata = serde_json::json!({
            "token": "token=abc123",
            "nested": {
                "args": ["safe", "sk-test"]
            }
        });
        let redacted = redact_metadata(&metadata);

        assert_eq!(redacted["token"], "token=[REDACTED]");
        assert_eq!(redacted["nested"]["args"][1], "[REDACTED_SECRET]");
    }

    #[test]
    fn csv_rows_escape_commas_and_quotes() {
        let row = csv_row(&["simple", "has,comma", "has\"quote"]);
        assert_eq!(row, "simple,\"has,comma\",\"has\"\"quote\"");
    }

    #[test]
    fn list_filtered_applies_actor_decision_and_action() {
        let path = std::env::temp_dir().join(format!("agentfence-audit-{}.sqlite", Uuid::new_v4()));
        let store = AuditStore::open(&path).expect("open audit store");

        store
            .append(&AuditEvent::new(
                "codex",
                "shell.exec",
                "git status",
                "allow",
                "low",
                "read-only",
            ))
            .expect("append codex shell event");
        store
            .append(&AuditEvent::new(
                "claude-code",
                "mcp.tool",
                "github/create_pull_request",
                "ask",
                "medium",
                "approval required",
            ))
            .expect("append claude mcp event");
        store
            .append(&AuditEvent::new(
                "codex",
                "mcp.tool",
                "github/list_pull_requests",
                "allow",
                "low",
                "allowed tool",
            ))
            .expect("append codex mcp event");

        let events = store
            .list_filtered(
                10,
                &AuditFilter {
                    actor: Some("codex".to_string()),
                    decision: Some("allow".to_string()),
                    action: Some("mcp.tool".to_string()),
                },
            )
            .expect("list filtered events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].subject, "github/list_pull_requests");

        drop(store);
        let _ = std::fs::remove_file(path);
    }
}

impl AuditStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create audit directory {}", parent.display())
            })?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("failed to open audit database {}", path.display()))?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn append(&self, event: &AuditEvent) -> Result<()> {
        let metadata = serde_json::to_string(&redact_metadata(&event.metadata))
            .context("failed to encode metadata")?;
        self.conn.execute(
            "insert into audit_events (
                id, timestamp, actor, action, subject, decision, risk, reason, matched_rule, cwd, metadata
             ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.id,
                event.timestamp.to_rfc3339(),
                event.actor,
                event.action,
                event.subject,
                event.decision,
                event.risk,
                event.reason,
                event.matched_rule,
                event.cwd,
                metadata,
            ],
        )?;
        Ok(())
    }

    pub fn list_recent(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "select id, timestamp, actor, action, subject, decision, risk, reason, matched_rule, cwd, metadata
             from audit_events
             order by timestamp desc
             limit ?1",
        )?;

        let rows = stmt.query_map([limit as i64], row_to_audit_event)?;

        collect_events(rows)
    }

    pub fn list_filtered(&self, limit: usize, filter: &AuditFilter) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "select id, timestamp, actor, action, subject, decision, risk, reason, matched_rule, cwd, metadata
             from audit_events
             where (?1 is null or actor = ?1)
               and (?2 is null or decision = ?2)
               and (?3 is null or action = ?3)
             order by timestamp desc
             limit ?4",
        )?;

        let actor = non_empty(filter.actor.as_deref());
        let decision = non_empty(filter.decision.as_deref());
        let action = non_empty(filter.action.as_deref());
        let rows = stmt.query_map(
            params![actor, decision, action, limit as i64],
            row_to_audit_event,
        )?;

        collect_events(rows)
    }

    pub fn export(&self, limit: usize, format: AuditExportFormat) -> Result<String> {
        let events = self.list_recent(limit)?;
        match format {
            AuditExportFormat::Json => {
                serde_json::to_string_pretty(&events).context("failed to encode audit JSON")
            }
            AuditExportFormat::Csv => Ok(events_to_csv(&events)),
        }
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "create table if not exists audit_events (
                id text primary key,
                timestamp text not null,
                actor text not null,
                action text not null,
                subject text not null,
                decision text not null,
                risk text not null,
                reason text not null,
                matched_rule text,
                cwd text,
                metadata text not null
            );
            create index if not exists idx_audit_events_timestamp on audit_events(timestamp);
            create index if not exists idx_audit_events_actor on audit_events(actor);
            create index if not exists idx_audit_events_decision on audit_events(decision);
            create index if not exists idx_audit_events_action on audit_events(action);",
        )?;
        Ok(())
    }
}

fn row_to_audit_event(row: &Row<'_>) -> rusqlite::Result<AuditEvent> {
    let timestamp: String = row.get(1)?;
    let metadata: String = row.get(10)?;

    Ok(AuditEvent {
        id: row.get(0)?,
        timestamp: DateTime::parse_from_rfc3339(&timestamp)
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        actor: row.get(2)?,
        action: row.get(3)?,
        subject: row.get(4)?,
        decision: row.get(5)?,
        risk: row.get(6)?,
        reason: row.get(7)?,
        matched_rule: row.get(8)?,
        cwd: row.get(9)?,
        metadata: serde_json::from_str(&metadata).unwrap_or(Value::Null),
    })
}

fn collect_events<F>(rows: MappedRows<'_, F>) -> Result<Vec<AuditEvent>>
where
    F: FnMut(&Row<'_>) -> rusqlite::Result<AuditEvent>,
{
    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }

    Ok(events)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn events_to_csv(events: &[AuditEvent]) -> String {
    let mut output =
        String::from("id,timestamp,actor,action,subject,decision,risk,reason,matched_rule,cwd\n");
    for event in events {
        output.push_str(&csv_row(&[
            &event.id,
            &event.timestamp.to_rfc3339(),
            &event.actor,
            &event.action,
            &event.subject,
            &event.decision,
            &event.risk,
            &event.reason,
            event.matched_rule.as_deref().unwrap_or_default(),
            event.cwd.as_deref().unwrap_or_default(),
        ]));
        output.push('\n');
    }
    output
}

fn csv_row(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| {
            if field.contains(',') || field.contains('"') || field.contains('\n') {
                format!("\"{}\"", field.replace('"', "\"\""))
            } else {
                field.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}
