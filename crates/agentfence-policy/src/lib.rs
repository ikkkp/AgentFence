use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy file was not found from {0}")]
    NotFound(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Ask,
    AllowOnce,
    AllowForSession,
    AllowWithConstraints,
}

impl Default for Decision {
    fn default() -> Self {
        Self::Ask
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Risk {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub version: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub default_decision: Decision,
    #[serde(default)]
    pub actors: BTreeMap<String, ActorPolicy>,
    #[serde(default)]
    pub shell: ShellPolicy,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub mcp: McpPolicy,
    #[serde(default)]
    pub skills: SkillPolicy,
    #[serde(default)]
    pub approval: ApprovalPolicy,
    #[serde(default)]
    pub audit: AuditPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyPreset {
    ReadOnly,
    Developer,
    Strict,
    TrustedProject,
    CiLike,
}

impl std::str::FromStr for PolicyPreset {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "read-only" | "readonly" => Ok(Self::ReadOnly),
            "developer" | "dev" => Ok(Self::Developer),
            "strict" => Ok(Self::Strict),
            "trusted-project" | "trusted" => Ok(Self::TrustedProject),
            "ci-like" | "ci" => Ok(Self::CiLike),
            _ => bail!("unknown policy preset {value}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBundle {
    pub bundle_version: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    pub policy: Policy,
    pub digest: String,
    #[serde(default)]
    pub signature: Option<PolicyBundleSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBundleSignature {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBundleKeyPair {
    pub algorithm: String,
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleVerification {
    pub valid: bool,
    pub digest_valid: bool,
    pub expected_digest: String,
    pub actual_digest: String,
    #[serde(default)]
    pub signature_present: bool,
    #[serde(default)]
    pub signature_valid: Option<bool>,
    #[serde(default)]
    pub signature_error: Option<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: "0.1".to_string(),
            project: None,
            default_decision: Decision::Ask,
            actors: BTreeMap::new(),
            shell: ShellPolicy::default(),
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            mcp: McpPolicy::default(),
            skills: SkillPolicy::default(),
            approval: ApprovalPolicy::default(),
            audit: AuditPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActorPolicy {
    #[serde(default)]
    pub trust_level: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShellPolicy {
    #[serde(default)]
    pub rules: Vec<ShellRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShellRule {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub r#match: ShellMatch,
    pub decision: Decision,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShellMatch {
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub risks: Vec<Risk>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub allow_roots: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
    #[serde(default)]
    pub write: FilesystemWritePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemWritePolicy {
    #[serde(default)]
    pub decision: Decision,
    #[serde(default)]
    pub allow_extensions: Vec<String>,
}

impl Default for FilesystemWritePolicy {
    fn default() -> Self {
        Self {
            decision: Decision::Ask,
            allow_extensions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    #[serde(default)]
    pub default_decision: Decision,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default)]
    pub deny_domains: Vec<String>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            default_decision: Decision::Ask,
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpPolicy {
    #[serde(default)]
    pub servers: BTreeMap<String, McpServerPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpServerPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "RateLimitPolicy::is_disabled")]
    pub rate_limit: RateLimitPolicy,
    #[serde(default)]
    pub tools: BTreeMap<String, Decision>,
    #[serde(default)]
    pub resources: BTreeMap<String, Decision>,
    #[serde(default)]
    pub prompts: BTreeMap<String, Decision>,
}

impl Default for McpServerPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            decision: Decision::Ask,
            rate_limit: RateLimitPolicy::default(),
            tools: BTreeMap::new(),
            resources: BTreeMap::new(),
            prompts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rate_limit_max_requests")]
    pub max_requests: u32,
    #[serde(default = "default_rate_limit_window_seconds")]
    pub window_seconds: u64,
}

impl RateLimitPolicy {
    pub fn is_disabled(&self) -> bool {
        !self.enabled
    }
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_requests: default_rate_limit_max_requests(),
            window_seconds: default_rate_limit_window_seconds(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkillPolicy {
    #[serde(default)]
    pub default_decision: Decision,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub rules: Vec<SkillRule>,
}

impl Default for SkillPolicy {
    fn default() -> Self {
        Self {
            default_decision: Decision::Ask,
            allow: Vec::new(),
            deny: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkillRule {
    pub skill: String,
    pub decision: Decision,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalPolicy {
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    #[serde(default = "default_true")]
    pub remember_choices: bool,
    #[serde(default = "default_true")]
    pub require_reason_for_high_risk: bool,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            ttl_seconds: default_ttl(),
            remember_choices: true,
            require_reason_for_high_risk: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_store")]
    pub store: String,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            store: default_audit_store(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellRequest {
    pub actor: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: String,
    pub risk: Risk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionResult {
    pub decision: Decision,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub risk: Risk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemRequest {
    pub operation: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRequest {
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillRequest {
    pub skill: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPatchProposal {
    pub summary: String,
    pub operations: Vec<JsonPatchOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct JsonPatchOperation {
    pub op: String,
    pub path: String,
    pub value: serde_json::Value,
}

pub fn load_policy(path: impl AsRef<Path>) -> Result<Policy> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file {}", path.display()))?;
    let policy: Policy = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy file {}", path.display()))?;
    Ok(policy)
}

pub fn save_policy(path: impl AsRef<Path>, policy: &Policy) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create policy directory {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(policy).context("failed to serialize policy")?;
    fs::write(path, raw).with_context(|| format!("failed to write policy {}", path.display()))?;
    Ok(())
}

pub fn discover_policy(start: impl AsRef<Path>) -> Result<PathBuf> {
    let mut current = start.as_ref().to_path_buf();
    if current.is_file() {
        current.pop();
    }

    loop {
        let candidate = current.join("agentfence.policy.json");
        if candidate.exists() {
            return Ok(candidate);
        }

        if !current.pop() {
            return Err(PolicyError::NotFound(start.as_ref().to_path_buf()).into());
        }
    }
}

pub fn evaluate_shell(policy: &Policy, request: &ShellRequest) -> DecisionResult {
    for rule in &policy.shell.rules {
        if shell_rule_matches(rule, request) {
            return DecisionResult {
                decision: rule.decision,
                reason: rule
                    .reason
                    .clone()
                    .or_else(|| rule.description.clone())
                    .unwrap_or_else(|| format!("matched shell rule {}", rule.id)),
                matched_rule: Some(rule.id.clone()),
                risk: request.risk,
            };
        }
    }

    DecisionResult {
        decision: policy.default_decision,
        reason: "no matching rule; using default decision".to_string(),
        matched_rule: None,
        risk: request.risk,
    }
}

pub fn evaluate_mcp(policy: &Policy, server: &str, kind: &str, name: &str) -> DecisionResult {
    let risk = Risk::Medium;
    let Some(server_policy) = policy.mcp.servers.get(server) else {
        return DecisionResult {
            decision: policy.default_decision,
            reason: format!("MCP server {server} has no explicit policy"),
            matched_rule: None,
            risk,
        };
    };

    if !server_policy.enabled {
        return DecisionResult {
            decision: Decision::Deny,
            reason: format!("MCP server {server} is disabled"),
            matched_rule: Some(format!("mcp.servers.{server}.enabled")),
            risk,
        };
    }

    let decision = match kind {
        "tool" => server_policy.tools.get(name),
        "resource" => server_policy.resources.get(name),
        "prompt" => server_policy.prompts.get(name),
        _ => None,
    };

    if let Some(decision) = decision {
        return DecisionResult {
            decision: *decision,
            reason: format!("matched MCP {kind} policy for {server}/{name}"),
            matched_rule: Some(format!("mcp.servers.{server}.{kind}s.{name}")),
            risk,
        };
    }

    DecisionResult {
        decision: server_policy.decision,
        reason: format!("using default MCP server decision for {server}"),
        matched_rule: Some(format!("mcp.servers.{server}.decision")),
        risk,
    }
}

pub fn evaluate_filesystem(policy: &Policy, request: &FilesystemRequest) -> DecisionResult {
    let normalized_path = normalize_pathish(&request.path);
    let operation = request.operation.to_ascii_lowercase();

    if let Some(deny_path) = policy
        .filesystem
        .deny_paths
        .iter()
        .find(|path| path_matches(&normalized_path, &normalize_pathish(path)))
    {
        return DecisionResult {
            decision: Decision::Deny,
            reason: format!("path matches denied filesystem entry {deny_path}"),
            matched_rule: Some("filesystem.denyPaths".to_string()),
            risk: Risk::Critical,
        };
    }

    if operation == "write" || operation == "delete" || operation == "move" {
        if operation == "write"
            && extension_allowed(&normalized_path, &policy.filesystem.write.allow_extensions)
        {
            return DecisionResult {
                decision: policy.filesystem.write.decision,
                reason: "write path extension matched filesystem write policy".to_string(),
                matched_rule: Some("filesystem.write".to_string()),
                risk: Risk::High,
            };
        }

        return DecisionResult {
            decision: policy.filesystem.write.decision,
            reason: "filesystem write-like operation requires policy decision".to_string(),
            matched_rule: Some("filesystem.write.decision".to_string()),
            risk: Risk::High,
        };
    }

    if policy.filesystem.allow_roots.is_empty()
        || policy
            .filesystem
            .allow_roots
            .iter()
            .any(|root| path_matches(&normalized_path, &normalize_pathish(root)))
    {
        return DecisionResult {
            decision: Decision::Allow,
            reason: "path is inside an allowed filesystem root".to_string(),
            matched_rule: Some("filesystem.allowRoots".to_string()),
            risk: Risk::Low,
        };
    }

    DecisionResult {
        decision: policy.default_decision,
        reason: "path did not match an allowed filesystem root".to_string(),
        matched_rule: None,
        risk: Risk::Medium,
    }
}

pub fn evaluate_network(policy: &Policy, request: &NetworkRequest) -> DecisionResult {
    let domain = normalize_domain(&request.domain);

    if let Some(denied) = policy
        .network
        .deny_domains
        .iter()
        .find(|candidate| domain_matches(&domain, &normalize_domain(candidate)))
    {
        return DecisionResult {
            decision: Decision::Deny,
            reason: format!("domain matches denied network entry {denied}"),
            matched_rule: Some("network.denyDomains".to_string()),
            risk: Risk::High,
        };
    }

    if let Some(allowed) = policy
        .network
        .allow_domains
        .iter()
        .find(|candidate| domain_matches(&domain, &normalize_domain(candidate)))
    {
        return DecisionResult {
            decision: Decision::Allow,
            reason: format!("domain matches allowed network entry {allowed}"),
            matched_rule: Some("network.allowDomains".to_string()),
            risk: Risk::Medium,
        };
    }

    DecisionResult {
        decision: policy.network.default_decision,
        reason: "domain did not match an explicit network rule".to_string(),
        matched_rule: Some("network.defaultDecision".to_string()),
        risk: Risk::Medium,
    }
}

pub fn evaluate_skill(policy: &Policy, request: &SkillRequest) -> DecisionResult {
    let skill = request.skill.to_ascii_lowercase();

    if let Some(rule) = policy
        .skills
        .rules
        .iter()
        .find(|rule| rule.skill.eq_ignore_ascii_case(&skill))
    {
        return DecisionResult {
            decision: rule.decision,
            reason: rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("matched skill rule {}", rule.skill)),
            matched_rule: Some(format!("skills.rules.{}", rule.skill)),
            risk: Risk::Medium,
        };
    }

    if policy
        .skills
        .deny
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&skill))
    {
        return DecisionResult {
            decision: Decision::Deny,
            reason: format!("skill {skill} is explicitly denied"),
            matched_rule: Some("skills.deny".to_string()),
            risk: Risk::High,
        };
    }

    if policy
        .skills
        .allow
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&skill))
    {
        return DecisionResult {
            decision: Decision::Allow,
            reason: format!("skill {skill} is explicitly allowed"),
            matched_rule: Some("skills.allow".to_string()),
            risk: Risk::Low,
        };
    }

    DecisionResult {
        decision: policy.skills.default_decision,
        reason: "skill did not match an explicit rule".to_string(),
        matched_rule: Some("skills.defaultDecision".to_string()),
        risk: Risk::Medium,
    }
}

pub fn default_policy(project: Option<String>) -> Policy {
    let mut actors = BTreeMap::new();
    actors.insert(
        "codex".to_string(),
        ActorPolicy {
            trust_level: Some("medium".to_string()),
        },
    );
    actors.insert(
        "claude-code".to_string(),
        ActorPolicy {
            trust_level: Some("medium".to_string()),
        },
    );

    Policy {
        project,
        actors,
        shell: ShellPolicy {
            rules: vec![
                ShellRule {
                    id: "allow-readonly".to_string(),
                    description: Some("Allow common read-only inspection commands.".to_string()),
                    r#match: ShellMatch {
                        commands: vec![
                            "pwd".to_string(),
                            "ls".to_string(),
                            "dir".to_string(),
                            "rg".to_string(),
                            "grep".to_string(),
                            "cat".to_string(),
                            "type".to_string(),
                            "git status".to_string(),
                            "git diff".to_string(),
                        ],
                        patterns: Vec::new(),
                        risks: vec![Risk::Low],
                    },
                    decision: Decision::Allow,
                    reason: Some("read-only inspection is allowed".to_string()),
                },
                ShellRule {
                    id: "ask-package-install".to_string(),
                    description: Some(
                        "Ask before dependency or toolchain installation.".to_string(),
                    ),
                    r#match: ShellMatch {
                        commands: vec![
                            "npm install".to_string(),
                            "pnpm install".to_string(),
                            "yarn install".to_string(),
                            "pip install".to_string(),
                            "cargo install".to_string(),
                        ],
                        patterns: Vec::new(),
                        risks: vec![Risk::High],
                    },
                    decision: Decision::Ask,
                    reason: Some("package installation can modify the environment".to_string()),
                },
                ShellRule {
                    id: "deny-dangerous-delete".to_string(),
                    description: Some(
                        "Deny destructive delete commands targeting broad roots.".to_string(),
                    ),
                    r#match: ShellMatch {
                        commands: Vec::new(),
                        patterns: vec![
                            "rm -rf /".to_string(),
                            "rm -rf ~".to_string(),
                            "del /s".to_string(),
                            "format ".to_string(),
                        ],
                        risks: vec![Risk::Critical],
                    },
                    decision: Decision::Deny,
                    reason: Some("dangerous broad deletion is denied".to_string()),
                },
            ],
        },
        filesystem: FilesystemPolicy {
            allow_roots: vec!["./".to_string()],
            deny_paths: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "~/.config".to_string(),
                ".env".to_string(),
                "secrets.json".to_string(),
            ],
            write: FilesystemWritePolicy {
                decision: Decision::Ask,
                allow_extensions: vec![
                    ".rs".to_string(),
                    ".ts".to_string(),
                    ".tsx".to_string(),
                    ".js".to_string(),
                    ".py".to_string(),
                    ".md".to_string(),
                    ".json".to_string(),
                ],
            },
        },
        network: NetworkPolicy {
            default_decision: Decision::Ask,
            allow_domains: vec![
                "github.com".to_string(),
                "registry.npmjs.org".to_string(),
                "pypi.org".to_string(),
                "crates.io".to_string(),
            ],
            deny_domains: vec!["pastebin.com".to_string(), "transfer.sh".to_string()],
        },
        skills: SkillPolicy {
            default_decision: Decision::Ask,
            allow: vec![
                "code-review".to_string(),
                "test-runner".to_string(),
                "docs-editor".to_string(),
            ],
            deny: vec!["deploy-production".to_string()],
            rules: Vec::new(),
        },
        ..Policy::default()
    }
}

pub fn preset_policy(preset: PolicyPreset, project: Option<String>) -> Policy {
    let mut policy = default_policy(project);

    match preset {
        PolicyPreset::ReadOnly => {
            policy.default_decision = Decision::Deny;
            policy.filesystem.write.decision = Decision::Deny;
            policy.network.default_decision = Decision::Deny;
            policy.skills.default_decision = Decision::Deny;
            policy
                .shell
                .rules
                .retain(|rule| rule.id == "allow-readonly");
        }
        PolicyPreset::Developer => {
            policy.default_decision = Decision::Ask;
        }
        PolicyPreset::Strict => {
            policy.default_decision = Decision::Ask;
            policy.filesystem.write.decision = Decision::Ask;
            policy.network.default_decision = Decision::Ask;
            policy.skills.default_decision = Decision::Ask;
            policy.shell.rules.push(ShellRule {
                id: "deny-production-deploy".to_string(),
                description: Some("Deny production deployment commands.".to_string()),
                r#match: ShellMatch {
                    commands: Vec::new(),
                    patterns: vec![
                        "deploy production".to_string(),
                        "vercel --prod".to_string(),
                        "fly deploy".to_string(),
                        "kubectl apply".to_string(),
                    ],
                    risks: Vec::new(),
                },
                decision: Decision::Deny,
                reason: Some("production deploys are denied by strict preset".to_string()),
            });
        }
        PolicyPreset::TrustedProject => {
            policy.default_decision = Decision::Ask;
            policy.filesystem.write.decision = Decision::Allow;
            policy.shell.rules.push(ShellRule {
                id: "allow-common-builds".to_string(),
                description: Some("Allow common local build and test commands.".to_string()),
                r#match: ShellMatch {
                    commands: vec![
                        "cargo build".to_string(),
                        "cargo test".to_string(),
                        "npm test".to_string(),
                        "pnpm test".to_string(),
                        "pytest".to_string(),
                    ],
                    patterns: Vec::new(),
                    risks: Vec::new(),
                },
                decision: Decision::Allow,
                reason: Some("trusted project can run local verification commands".to_string()),
            });
        }
        PolicyPreset::CiLike => {
            policy.default_decision = Decision::Deny;
            policy.filesystem.write.decision = Decision::Ask;
            policy.network.default_decision = Decision::Deny;
            policy.shell.rules.push(ShellRule {
                id: "allow-ci-verification".to_string(),
                description: Some(
                    "Allow deterministic CI-style verification commands.".to_string(),
                ),
                r#match: ShellMatch {
                    commands: vec![
                        "cargo test".to_string(),
                        "cargo fmt --check".to_string(),
                        "pnpm typecheck".to_string(),
                        "pnpm build".to_string(),
                    ],
                    patterns: Vec::new(),
                    risks: Vec::new(),
                },
                decision: Decision::Allow,
                reason: Some("CI-style verification is allowed".to_string()),
            });
        }
    }

    policy
}

pub fn create_policy_bundle(
    name: impl Into<String>,
    description: Option<String>,
    organization: Option<String>,
    policy: Policy,
) -> Result<PolicyBundle> {
    let digest = policy_digest(&policy)?;
    Ok(PolicyBundle {
        bundle_version: "0.1".to_string(),
        name: name.into(),
        description,
        organization,
        policy,
        digest,
        signature: None,
    })
}

pub fn verify_policy_bundle(bundle: &PolicyBundle) -> Result<BundleVerification> {
    let actual_digest = policy_digest(&bundle.policy)?;
    let digest_valid = bundle.digest == actual_digest;
    let (signature_valid, signature_error) = match &bundle.signature {
        Some(signature) => match verify_policy_bundle_signature(&bundle.digest, signature) {
            Ok(valid) => (Some(valid), None),
            Err(error) => (Some(false), Some(error.to_string())),
        },
        None => (None, None),
    };
    let valid = digest_valid && signature_valid.unwrap_or(true);
    Ok(BundleVerification {
        valid,
        digest_valid,
        expected_digest: bundle.digest.clone(),
        actual_digest,
        signature_present: bundle.signature.is_some(),
        signature_valid,
        signature_error,
    })
}

pub fn generate_policy_bundle_keypair() -> PolicyBundleKeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    PolicyBundleKeyPair {
        algorithm: "ed25519".to_string(),
        public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
        secret_key: BASE64.encode(signing_key.to_bytes()),
    }
}

pub fn sign_policy_bundle(bundle: &mut PolicyBundle, keypair: &PolicyBundleKeyPair) -> Result<()> {
    if keypair.algorithm != "ed25519" {
        bail!(
            "unsupported policy bundle key algorithm {}",
            keypair.algorithm
        );
    }
    let secret = decode_base64_array::<32>(&keypair.secret_key)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let signature = signing_key.sign(signing_payload(&bundle.digest).as_bytes());
    bundle.signature = Some(PolicyBundleSignature {
        algorithm: "ed25519".to_string(),
        public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
        signature: BASE64.encode(signature.to_bytes()),
    });
    Ok(())
}

pub fn verify_policy_bundle_signature(
    digest: &str,
    signature: &PolicyBundleSignature,
) -> Result<bool> {
    if signature.algorithm != "ed25519" {
        bail!(
            "unsupported policy bundle signature algorithm {}",
            signature.algorithm
        );
    }
    let public_key = decode_base64_array::<32>(&signature.public_key)?;
    let signature_bytes = BASE64
        .decode(&signature.signature)
        .context("failed to decode bundle signature")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).context("invalid bundle public key")?;
    let signature = Signature::from_slice(&signature_bytes).context("invalid bundle signature")?;
    Ok(verifying_key
        .verify(signing_payload(digest).as_bytes(), &signature)
        .is_ok())
}

pub fn policy_digest(policy: &Policy) -> Result<String> {
    let raw = serde_json::to_vec(policy).context("failed to serialize policy for digest")?;
    let digest = Sha256::digest(raw);
    Ok(format!("sha256:{}", hex_lower(&digest)))
}

fn signing_payload(digest: &str) -> String {
    format!("agentfence-policy-bundle-v1\0{digest}")
}

fn decode_base64_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = BASE64.decode(value).context("failed to decode base64")?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("expected {N} bytes, got {}", bytes.len()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn policy_schema_json() -> Result<String> {
    let schema = schemars::schema_for!(Policy);
    serde_json::to_string_pretty(&schema).context("failed to serialize policy schema")
}

pub fn propose_policy_patch(instruction: &str) -> PolicyPatchProposal {
    let lower = instruction.to_ascii_lowercase();
    let mut operations = Vec::new();

    if contains_any(
        &lower,
        &["test", "tests", "测试", "cargo test", "npm test", "pytest"],
    ) {
        operations.push(JsonPatchOperation {
            op: "add".to_string(),
            path: "/shell/rules/-".to_string(),
            value: serde_json::json!({
                "id": "allow-local-tests",
                "description": "Allow common local test commands.",
                "match": {
                    "commands": ["cargo test", "npm test", "pnpm test", "pytest"]
                },
                "decision": "allow",
                "reason": "local test commands are allowed"
            }),
        });
    }

    if contains_any(
        &lower,
        &["install", "dependency", "dependencies", "依赖", "安装"],
    ) {
        operations.push(JsonPatchOperation {
            op: "add".to_string(),
            path: "/shell/rules/-".to_string(),
            value: serde_json::json!({
                "id": "ask-package-install",
                "description": "Ask before installing dependencies.",
                "match": {
                    "commands": ["npm install", "pnpm install", "yarn install", "pip install", "cargo install"],
                    "risks": ["high"]
                },
                "decision": "ask",
                "reason": "dependency installation can modify the environment"
            }),
        });
    }

    if contains_any(
        &lower,
        &[
            "deploy",
            "production",
            "prod",
            "发布生产",
            "生产部署",
            "部署",
        ],
    ) {
        operations.push(JsonPatchOperation {
            op: "add".to_string(),
            path: "/shell/rules/-".to_string(),
            value: serde_json::json!({
                "id": "deny-production-deploy",
                "description": "Deny production deployment commands.",
                "match": {
                    "patterns": ["deploy production", "vercel --prod", "fly deploy", "kubectl apply"]
                },
                "decision": "deny",
                "reason": "production deployments are denied by policy"
            }),
        });
        operations.push(JsonPatchOperation {
            op: "add".to_string(),
            path: "/skills/deny/-".to_string(),
            value: serde_json::json!("deploy-production"),
        });
    }

    if contains_any(&lower, &["network", "domain", "网络", "域名", "外部请求"]) {
        operations.push(JsonPatchOperation {
            op: "replace".to_string(),
            path: "/network/defaultDecision".to_string(),
            value: serde_json::json!("ask"),
        });
    }

    if contains_any(&lower, &["read-only", "readonly", "只读"]) {
        operations.push(JsonPatchOperation {
            op: "replace".to_string(),
            path: "/defaultDecision".to_string(),
            value: serde_json::json!("deny"),
        });
        operations.push(JsonPatchOperation {
            op: "replace".to_string(),
            path: "/filesystem/write/decision".to_string(),
            value: serde_json::json!("deny"),
        });
    }

    if operations.is_empty() {
        operations.push(JsonPatchOperation {
            op: "test".to_string(),
            path: "/version".to_string(),
            value: serde_json::json!("0.1"),
        });
    }

    PolicyPatchProposal {
        summary: if operations.len() == 1 && operations[0].op == "test" {
            "No safe automatic policy change was inferred; review the instruction manually."
                .to_string()
        } else {
            format!(
                "Generated {} policy patch operation(s) from the instruction.",
                operations.len()
            )
        },
        operations,
    }
}

pub fn apply_policy_patch(
    value: &mut serde_json::Value,
    operations: &[JsonPatchOperation],
) -> Result<()> {
    for operation in operations {
        match operation.op.as_str() {
            "add" => json_pointer_add(value, &operation.path, operation.value.clone())?,
            "replace" => json_pointer_replace(value, &operation.path, operation.value.clone())?,
            "test" => json_pointer_test(value, &operation.path, &operation.value)?,
            op => bail!("unsupported JSON Patch operation {op}"),
        }
    }

    let _: Policy = serde_json::from_value(value.clone()).context("patched policy is invalid")?;
    Ok(())
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn json_pointer_add(
    root: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> Result<()> {
    let tokens = json_pointer_tokens(path)?;
    if tokens.is_empty() {
        *root = value;
        return Ok(());
    }

    let (parent_tokens, last) = tokens.split_at(tokens.len() - 1);
    let parent = pointer_mut_tokens(root, parent_tokens)?;
    let key = &last[0];

    match parent {
        serde_json::Value::Array(array) if key == "-" => {
            array.push(value);
            Ok(())
        }
        serde_json::Value::Array(array) => {
            let index = key
                .parse::<usize>()
                .with_context(|| format!("invalid JSON pointer array index {key}"))?;
            if index > array.len() {
                bail!("JSON pointer array index {index} is out of bounds");
            }
            array.insert(index, value);
            Ok(())
        }
        serde_json::Value::Object(object) => {
            object.insert(key.clone(), value);
            Ok(())
        }
        _ => bail!("JSON pointer parent at {path} is not an array or object"),
    }
}

fn json_pointer_replace(
    root: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> Result<()> {
    let Some(target) = root.pointer_mut(path) else {
        bail!("JSON pointer {path} does not exist for replace");
    };
    *target = value;
    Ok(())
}

fn json_pointer_test(
    root: &serde_json::Value,
    path: &str,
    expected: &serde_json::Value,
) -> Result<()> {
    let Some(actual) = root.pointer(path) else {
        bail!("JSON pointer {path} does not exist for test");
    };
    if actual != expected {
        bail!("JSON pointer test failed at {path}");
    }
    Ok(())
}

fn pointer_mut_tokens<'a>(
    mut value: &'a mut serde_json::Value,
    tokens: &[String],
) -> Result<&'a mut serde_json::Value> {
    for token in tokens {
        match value {
            serde_json::Value::Object(object) => {
                value = object
                    .get_mut(token)
                    .with_context(|| format!("JSON pointer object key {token} was not found"))?;
            }
            serde_json::Value::Array(array) => {
                let index = token
                    .parse::<usize>()
                    .with_context(|| format!("invalid JSON pointer array index {token}"))?;
                value = array
                    .get_mut(index)
                    .with_context(|| format!("JSON pointer array index {index} was not found"))?;
            }
            _ => bail!("JSON pointer target is not traversable"),
        }
    }
    Ok(value)
}

fn json_pointer_tokens(path: &str) -> Result<Vec<String>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if !path.starts_with('/') {
        bail!("JSON pointer must start with /: {path}");
    }
    Ok(path
        .split('/')
        .skip(1)
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect())
}

fn shell_rule_matches(rule: &ShellRule, request: &ShellRequest) -> bool {
    if rule.r#match.risks.contains(&request.risk) {
        return true;
    }

    let command = normalize_command(&request.command);
    for expected in &rule.r#match.commands {
        if command_matches(&command, &normalize_command(expected)) {
            return true;
        }
    }

    let full = normalize_command(&request.command);
    rule.r#match
        .patterns
        .iter()
        .any(|pattern| glob_like_match(&full, &normalize_command(pattern)))
}

fn command_matches(actual: &str, expected: &str) -> bool {
    actual == expected || actual.starts_with(&format!("{expected} "))
}

fn normalize_command(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn normalize_pathish(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn path_matches(path: &str, candidate: &str) -> bool {
    if candidate == "." || candidate == "./" || candidate.is_empty() {
        return true;
    }
    path == candidate
        || path.starts_with(&format!("{candidate}/"))
        || path.ends_with(&format!("/{candidate}"))
        || path.contains(&format!("/{candidate}/"))
}

fn extension_allowed(path: &str, extensions: &[String]) -> bool {
    if extensions.is_empty() {
        return false;
    }
    extensions
        .iter()
        .any(|extension| path.ends_with(&extension.to_ascii_lowercase()))
}

fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_start_matches("www.")
        .to_ascii_lowercase()
}

fn domain_matches(domain: &str, candidate: &str) -> bool {
    domain == candidate || domain.ends_with(&format!(".{candidate}"))
}

fn glob_like_match(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return value.contains(pattern);
    }

    let mut remaining = value;
    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
    }
    true
}

fn default_true() -> bool {
    true
}

fn default_rate_limit_max_requests() -> u32 {
    60
}

fn default_rate_limit_window_seconds() -> u64 {
    60
}

fn default_ttl() -> u64 {
    900
}

fn default_audit_store() -> String {
    ".agentfence/audit.sqlite".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_allows_readonly_commands() {
        let policy = default_policy(Some("demo".to_string()));
        let result = evaluate_shell(
            &policy,
            &ShellRequest {
                actor: "codex".to_string(),
                command: "git status --short".to_string(),
                args: vec!["status".to_string(), "--short".to_string()],
                cwd: ".".to_string(),
                risk: Risk::Low,
            },
        );

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.matched_rule.as_deref(), Some("allow-readonly"));
    }

    #[test]
    fn default_policy_denies_critical_deletes() {
        let policy = default_policy(Some("demo".to_string()));
        let result = evaluate_shell(
            &policy,
            &ShellRequest {
                actor: "codex".to_string(),
                command: "rm -rf /".to_string(),
                args: Vec::new(),
                cwd: ".".to_string(),
                risk: Risk::Critical,
            },
        );

        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn filesystem_denies_sensitive_paths() {
        let policy = default_policy(Some("demo".to_string()));
        let result = evaluate_filesystem(
            &policy,
            &FilesystemRequest {
                operation: "read".to_string(),
                path: "~/.ssh/id_rsa".to_string(),
            },
        );

        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn network_denies_configured_domains() {
        let policy = default_policy(Some("demo".to_string()));
        let result = evaluate_network(
            &policy,
            &NetworkRequest {
                domain: "https://transfer.sh/file".to_string(),
            },
        );

        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn skill_allows_configured_skills() {
        let policy = default_policy(Some("demo".to_string()));
        let result = evaluate_skill(
            &policy,
            &SkillRequest {
                skill: "code-review".to_string(),
            },
        );

        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn policy_assistant_proposes_test_and_install_rules() {
        let proposal = propose_policy_patch("允许 Codex 运行测试，但安装依赖需要确认");

        assert!(proposal.operations.len() >= 2);
        assert!(
            proposal
                .operations
                .iter()
                .any(|operation| operation.path == "/shell/rules/-")
        );
    }

    #[test]
    fn policy_assistant_proposes_deploy_denials() {
        let proposal = propose_policy_patch("禁止生产部署");

        assert!(
            proposal
                .operations
                .iter()
                .any(|operation| operation.path == "/skills/deny/-")
        );
    }

    #[test]
    fn applies_policy_patch_to_json_value() {
        let mut value = serde_json::to_value(default_policy(Some("demo".to_string()))).unwrap();
        let proposal = propose_policy_patch("allow tests but ask before dependency installs");

        apply_policy_patch(&mut value, &proposal.operations).expect("patch should apply");

        let policy: Policy = serde_json::from_value(value).expect("policy should remain valid");
        assert!(
            policy
                .shell
                .rules
                .iter()
                .any(|rule| rule.id == "allow-local-tests")
        );
    }

    #[test]
    fn rejects_failed_test_operation() {
        let mut value = serde_json::to_value(default_policy(Some("demo".to_string()))).unwrap();
        let result = apply_policy_patch(
            &mut value,
            &[JsonPatchOperation {
                op: "test".to_string(),
                path: "/version".to_string(),
                value: serde_json::json!("wrong"),
            }],
        );

        assert!(result.is_err());
    }

    #[test]
    fn read_only_preset_denies_writes_by_default() {
        let policy = preset_policy(PolicyPreset::ReadOnly, Some("demo".to_string()));

        assert_eq!(policy.default_decision, Decision::Deny);
        assert_eq!(policy.filesystem.write.decision, Decision::Deny);
        assert_eq!(policy.network.default_decision, Decision::Deny);
    }

    #[test]
    fn policy_bundle_verifies_digest_and_detects_tampering() {
        let policy = preset_policy(PolicyPreset::Strict, Some("demo".to_string()));
        let mut bundle = create_policy_bundle(
            "strict-demo",
            Some("Strict demo bundle".to_string()),
            Some("AgentFence".to_string()),
            policy,
        )
        .expect("bundle");

        let verification = verify_policy_bundle(&bundle).expect("verification");
        assert!(verification.valid);
        assert!(verification.digest_valid);

        bundle.policy.project = Some("tampered".to_string());
        let verification = verify_policy_bundle(&bundle).expect("verification");
        assert!(!verification.valid);
        assert!(!verification.digest_valid);
    }

    #[test]
    fn policy_bundle_signs_and_verifies_with_ed25519() {
        let policy = preset_policy(PolicyPreset::Strict, Some("demo".to_string()));
        let mut bundle =
            create_policy_bundle("strict-demo", None, Some("AgentFence".to_string()), policy)
                .expect("bundle");
        let keypair = generate_policy_bundle_keypair();

        sign_policy_bundle(&mut bundle, &keypair).expect("sign");
        let verification = verify_policy_bundle(&bundle).expect("verification");

        assert!(verification.valid);
        assert_eq!(verification.signature_valid, Some(true));

        bundle.digest = "sha256:bad".to_string();
        let verification = verify_policy_bundle(&bundle).expect("verification");
        assert!(!verification.valid);
        assert_eq!(verification.signature_valid, Some(false));
    }
}
