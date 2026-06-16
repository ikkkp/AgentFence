use std::collections::BTreeMap;

use agentfence_policy::{DecisionResult, Risk};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Allowed,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub risk: Risk,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub status: ApprovalStatus,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub resolution: Option<ApprovalResolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResolution {
    pub resolved_at: DateTime<Utc>,
    pub decision: ApprovalStatus,
    #[serde(default)]
    pub responder: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalCreate {
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub decision: DecisionResult,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResolve {
    pub decision: ApprovalStatus,
    #[serde(default)]
    pub responder: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Default)]
pub struct ApprovalQueue {
    requests: BTreeMap<String, ApprovalRequest>,
    ttl_seconds: i64,
}

impl ApprovalQueue {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            requests: BTreeMap::new(),
            ttl_seconds: ttl_seconds as i64,
        }
    }

    pub fn enqueue(&mut self, create: ApprovalCreate) -> ApprovalRequest {
        self.expire_old();
        let now = Utc::now();
        let request = ApprovalRequest {
            id: Uuid::new_v4().to_string(),
            created_at: now,
            expires_at: now + Duration::seconds(self.ttl_seconds),
            actor: create.actor,
            action: create.action,
            subject: create.subject,
            risk: create.decision.risk,
            reason: create.decision.reason,
            matched_rule: create.decision.matched_rule,
            status: ApprovalStatus::Pending,
            metadata: create.metadata,
            resolution: None,
        };
        self.requests.insert(request.id.clone(), request.clone());
        request
    }

    pub fn list(&mut self, status: Option<ApprovalStatus>) -> Vec<ApprovalRequest> {
        self.expire_old();
        let mut requests = self
            .requests
            .values()
            .filter(|request| status.is_none_or(|expected| request.status == expected))
            .cloned()
            .collect::<Vec<_>>();
        requests.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        requests
    }

    pub fn get(&mut self, id: &str) -> Option<ApprovalRequest> {
        self.expire_old();
        self.requests.get(id).cloned()
    }

    pub fn resolve(&mut self, id: &str, resolution: ApprovalResolve) -> Option<ApprovalRequest> {
        self.expire_old();
        let request = self.requests.get_mut(id)?;
        if request.status != ApprovalStatus::Pending {
            return Some(request.clone());
        }

        let decision = match resolution.decision {
            ApprovalStatus::Allowed => ApprovalStatus::Allowed,
            ApprovalStatus::Denied => ApprovalStatus::Denied,
            ApprovalStatus::Pending | ApprovalStatus::Expired => ApprovalStatus::Denied,
        };
        request.status = decision;
        request.resolution = Some(ApprovalResolution {
            resolved_at: Utc::now(),
            decision,
            responder: resolution.responder,
            reason: resolution.reason,
        });
        Some(request.clone())
    }

    fn expire_old(&mut self) {
        let now = Utc::now();
        for request in self.requests.values_mut() {
            if request.status == ApprovalStatus::Pending && request.expires_at <= now {
                request.status = ApprovalStatus::Expired;
                request.resolution = Some(ApprovalResolution {
                    resolved_at: now,
                    decision: ApprovalStatus::Expired,
                    responder: None,
                    reason: Some("approval request expired".to_string()),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use agentfence_policy::{Decision, Risk};

    use super::*;

    #[test]
    fn queue_enqueues_and_resolves_request() {
        let mut queue = ApprovalQueue::new(60);
        let request = queue.enqueue(ApprovalCreate {
            actor: "codex".to_string(),
            action: "shell.exec".to_string(),
            subject: "npm install".to_string(),
            decision: DecisionResult {
                decision: Decision::Ask,
                reason: "install requires approval".to_string(),
                matched_rule: Some("ask-package-install".to_string()),
                risk: Risk::High,
            },
            metadata: Value::Null,
        });

        assert_eq!(queue.list(Some(ApprovalStatus::Pending)).len(), 1);

        let resolved = queue
            .resolve(
                &request.id,
                ApprovalResolve {
                    decision: ApprovalStatus::Allowed,
                    responder: Some("user".to_string()),
                    reason: Some("needed for tests".to_string()),
                },
            )
            .expect("request should resolve");

        assert_eq!(resolved.status, ApprovalStatus::Allowed);
        assert_eq!(queue.list(Some(ApprovalStatus::Pending)).len(), 0);
    }
}
