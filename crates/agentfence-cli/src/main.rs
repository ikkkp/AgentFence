use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use agentfence_audit::{AuditEvent, AuditExportFormat, AuditStore};
use agentfence_policy::{
    Decision, DecisionResult, FilesystemRequest, NetworkRequest, PolicyBundle, PolicyBundleKeyPair,
    PolicyPreset, ShellRequest, SkillRequest, apply_policy_patch, create_policy_bundle,
    discover_policy, evaluate_filesystem, evaluate_network, evaluate_shell, evaluate_skill,
    generate_policy_bundle_keypair, load_policy, policy_schema_json, preset_policy,
    propose_policy_patch, save_policy, sign_policy_bundle, verify_policy_bundle,
};
use agentfence_shell::{classify_command, extract_network_domains};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "agentfence")]
#[command(about = "Local permission gateway for AI coding agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init(InitArgs),
    Run(RunArgs),
    Check(CheckArgs),
    Logs(LogsArgs),
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    Approvals {
        #[command(subcommand)]
        command: ApprovalCommands,
    },
    Approve(ApproveArgs),
    Filesystem {
        #[command(subcommand)]
        command: FilesystemCommands,
    },
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },
    Skill {
        #[command(subcommand)]
        command: SkillCommands,
    },
    Simulate {
        #[command(subcommand)]
        command: SimulateCommands,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long)]
    force: bool,
    #[arg(long)]
    project: Option<String>,
    #[arg(long, default_value = "developer")]
    preset: PolicyPresetArg,
}

#[derive(Debug, Clone)]
struct PolicyPresetArg(PolicyPreset);

impl std::str::FromStr for PolicyPresetArg {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(Self(value.parse()?))
    }
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long, default_value = "codex")]
    actor: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct CheckArgs {
    #[arg(long, default_value = "codex")]
    actor: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum SimulateCommands {
    Shell(SimulateShellArgs),
}

#[derive(Debug, Args)]
struct SimulateShellArgs {
    #[arg(long, default_value = "codex")]
    actor: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct LogsArgs {
    #[arg(long, default_value_t = 20)]
    limit: usize,
    #[arg(long)]
    audit: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum AuditCommands {
    Export {
        #[arg(long, default_value = "json")]
        format: AuditFormatArg,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        audit: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy)]
struct AuditFormatArg(AuditExportFormat);

impl std::str::FromStr for AuditFormatArg {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self(AuditExportFormat::Json)),
            "csv" => Ok(Self(AuditExportFormat::Csv)),
            _ => bail!("unknown audit export format {value}"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum ApprovalCommands {
    List {
        #[arg(long, default_value = "http://127.0.0.1:37421")]
        daemon: String,
        #[arg(long, default_value = "pending")]
        status: String,
    },
}

#[derive(Debug, Args)]
struct ApproveArgs {
    id: String,
    #[arg(long, default_value = "allowed")]
    decision: String,
    #[arg(long)]
    reason: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:37421")]
    daemon: String,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    Validate {
        #[arg(default_value = "agentfence.policy.json")]
        path: PathBuf,
    },
    Schema,
    Ask {
        instruction: Vec<String>,
    },
    Apply {
        #[arg(long, default_value = "agentfence.policy.json")]
        path: PathBuf,
        #[arg(long)]
        yes: bool,
        instruction: Vec<String>,
    },
    Bundle {
        #[command(subcommand)]
        command: PolicyBundleCommands,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyBundleCommands {
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    Export {
        #[arg(long, default_value = "agentfence.policy.json")]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "AgentFence Policy Bundle")]
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        organization: Option<String>,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    Verify {
        path: PathBuf,
    },
    Sign {
        path: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Import {
        path: PathBuf,
        #[arg(long, default_value = "agentfence.policy.json")]
        output: PathBuf,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        require_signature: bool,
    },
}

#[derive(Debug, Subcommand)]
enum FilesystemCommands {
    Check {
        #[arg(long)]
        operation: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum NetworkCommands {
    Check {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum SkillCommands {
    Check {
        #[arg(long)]
        name: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommands {
    Check {
        #[arg(long)]
        server: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    Proxy(McpProxyArgs),
}

#[derive(Debug, Args)]
struct McpProxyArgs {
    #[arg(long)]
    server: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long, default_value = "deny")]
    ask_mode: McpAskMode,
    #[arg(long, default_value = "http://127.0.0.1:37421")]
    daemon: String,
    #[arg(long, default_value_t = 900)]
    ask_timeout_seconds: u64,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum McpAskMode {
    Allow,
    Deny,
    Queue,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:?}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init(args) => init(args),
        Commands::Run(args) => run_guarded(args),
        Commands::Check(args) => check(args),
        Commands::Logs(args) => logs(args),
        Commands::Audit { command } => audit_command(command),
        Commands::Approvals { command } => approvals_command(command),
        Commands::Approve(args) => approve(args),
        Commands::Filesystem { command } => filesystem_command(command),
        Commands::Network { command } => network_command(command),
        Commands::Skill { command } => skill_command(command),
        Commands::Simulate { command } => simulate_command(command),
        Commands::Policy { command } => policy_command(command),
        Commands::Mcp { command } => mcp_command(command),
    }
}

fn init(args: InitArgs) -> Result<ExitCode> {
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = cwd.join("agentfence.policy.json");

    if policy_path.exists() && !args.force {
        bail!(
            "{} already exists; rerun with --force to replace it",
            policy_path.display()
        );
    }

    let project = args.project.or_else(|| {
        cwd.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.to_string())
    });
    let policy = preset_policy(args.preset.0, project);
    save_policy(&policy_path, &policy)?;

    let audit_dir = cwd.join(".agentfence");
    std::fs::create_dir_all(&audit_dir)
        .with_context(|| format!("failed to create {}", audit_dir.display()))?;

    println!("created {}", policy_path.display());
    println!("created {}", audit_dir.display());
    Ok(ExitCode::SUCCESS)
}

fn check(args: CheckArgs) -> Result<ExitCode> {
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = resolve_policy_path(args.policy.as_deref(), &cwd)?;
    let policy = load_policy(&policy_path)?;
    let command = classify_command(&args.command);
    let request = ShellRequest {
        actor: args.actor,
        command: command.command_line,
        args: args.command,
        cwd: cwd.display().to_string(),
        risk: command.risk,
    };
    let result = evaluate_shell(&policy, &request);
    let network_decisions = extract_network_domains(&request.args)
        .into_iter()
        .map(|domain| {
            let decision = evaluate_network(
                &policy,
                &NetworkRequest {
                    domain: domain.clone(),
                },
            );
            (domain, decision)
        })
        .collect::<Vec<_>>();

    println!("decision: {:?}", result.decision);
    println!("risk: {:?}", result.risk);
    println!("reason: {}", result.reason);
    if let Some(rule) = result.matched_rule {
        println!("matchedRule: {rule}");
    }
    for (domain, decision) in network_decisions {
        println!(
            "network[{domain}]: {:?} ({})",
            decision.decision, decision.reason
        );
    }

    Ok(ExitCode::SUCCESS)
}

fn run_guarded(args: RunArgs) -> Result<ExitCode> {
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = resolve_policy_path(args.policy.as_deref(), &cwd)?;
    let policy = load_policy(&policy_path)?;
    let command = classify_command(&args.command);
    let request = ShellRequest {
        actor: args.actor.clone(),
        command: command.command_line.clone(),
        args: args.command.clone(),
        cwd: cwd.display().to_string(),
        risk: command.risk,
    };
    let result = evaluate_shell(&policy, &request);
    let network_decisions = extract_network_domains(&args.command)
        .into_iter()
        .map(|domain| {
            let decision = evaluate_network(
                &policy,
                &NetworkRequest {
                    domain: domain.clone(),
                },
            );
            (domain, decision)
        })
        .collect::<Vec<_>>();

    let allowed = match result.decision {
        Decision::Allow
        | Decision::AllowOnce
        | Decision::AllowForSession
        | Decision::AllowWithConstraints => true,
        Decision::Deny => false,
        Decision::Ask => prompt_for_approval(&request.command, &result.reason)?,
    };
    let allowed = if allowed {
        approve_network_decisions(&network_decisions)?
    } else {
        false
    };
    let overall_risk = network_decisions
        .iter()
        .fold(result.risk, |risk, (_, decision)| risk.max(decision.risk));
    let reason = combined_shell_network_reason(&result, &network_decisions);
    let matched_rule = result.matched_rule.clone().or_else(|| {
        network_decisions
            .iter()
            .find_map(|(_, decision)| decision.matched_rule.clone())
    });
    let network_metadata = network_decisions
        .iter()
        .map(|(domain, decision)| {
            serde_json::json!({
                "domain": domain,
                "decision": decision.decision,
                "reason": &decision.reason,
                "matchedRule": &decision.matched_rule,
                "risk": decision.risk
            })
        })
        .collect::<Vec<_>>();

    let mut event = AuditEvent::new(
        args.actor,
        "shell.exec",
        request.command.clone(),
        if allowed { "allow" } else { "deny" },
        format!("{:?}", overall_risk).to_ascii_lowercase(),
        reason,
    );
    event.cwd = Some(request.cwd);
    event.matched_rule = matched_rule;
    event.metadata = serde_json::json!({
        "shell": {
            "decision": result.decision,
            "reason": result.reason.clone(),
            "matchedRule": result.matched_rule.clone(),
            "risk": result.risk
        },
        "network": network_metadata
    });

    if policy.audit.enabled {
        let audit_path = args
            .audit
            .unwrap_or_else(|| PathBuf::from(&policy.audit.store));
        AuditStore::open(audit_path)?.append(&event)?;
    }

    if !allowed {
        println!("denied: {}", request.command);
        return Ok(ExitCode::from(13));
    }

    let status = Command::new(&args.command[0])
        .args(&args.command[1..])
        .status()
        .with_context(|| format!("failed to execute {}", args.command[0]))?;

    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn logs(args: LogsArgs) -> Result<ExitCode> {
    let path = args
        .audit
        .unwrap_or_else(|| PathBuf::from(".agentfence/audit.sqlite"));
    let store = AuditStore::open(path)?;
    let events = store.list_recent(args.limit)?;

    for event in events {
        println!(
            "{} {} {} {} {}",
            event.timestamp.to_rfc3339(),
            event.actor,
            event.decision,
            event.risk,
            event.subject
        );
        println!("  {}", event.reason);
    }

    Ok(ExitCode::SUCCESS)
}

fn simulate_command(command: SimulateCommands) -> Result<ExitCode> {
    match command {
        SimulateCommands::Shell(args) => simulate_shell_command(args),
    }
}

fn simulate_shell_command(args: SimulateShellArgs) -> Result<ExitCode> {
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = resolve_policy_path(args.policy.as_deref(), &cwd)?;
    let policy = load_policy(&policy_path)?;
    let command = classify_command(&args.command);
    let request = ShellRequest {
        actor: args.actor,
        command: command.command_line,
        args: args.command,
        cwd: cwd.display().to_string(),
        risk: command.risk,
    };
    let shell_decision = evaluate_shell(&policy, &request);
    let network_decisions = extract_network_domains(&request.args)
        .into_iter()
        .map(|domain| {
            let decision = evaluate_network(
                &policy,
                &NetworkRequest {
                    domain: domain.clone(),
                },
            );
            serde_json::json!({
                "domain": domain,
                "decision": decision
            })
        })
        .collect::<Vec<_>>();
    let decision = effective_decision_from_json(&shell_decision, &network_decisions);
    let explanation = explain_simulation_json(&shell_decision, &network_decisions, &decision);

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "request": request,
            "decision": decision,
            "shellDecision": shell_decision,
            "summary": command.summary,
            "networkDecisions": network_decisions,
            "explanation": explanation
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn audit_command(command: AuditCommands) -> Result<ExitCode> {
    match command {
        AuditCommands::Export {
            format,
            limit,
            output,
            audit,
        } => {
            let path = audit.unwrap_or_else(|| PathBuf::from(".agentfence/audit.sqlite"));
            let store = AuditStore::open(path)?;
            let exported = store.export(limit, format.0)?;
            if let Some(output) = output {
                fs::write(&output, exported).with_context(|| {
                    format!("failed to write audit export {}", output.display())
                })?;
                println!("exported audit log to {}", output.display());
            } else {
                println!("{exported}");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn approvals_command(command: ApprovalCommands) -> Result<ExitCode> {
    match command {
        ApprovalCommands::List { daemon, status } => {
            let value =
                local_daemon_json(&daemon, "GET", &format!("/approvals?status={status}"), None)?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn approve(args: ApproveArgs) -> Result<ExitCode> {
    let body = serde_json::json!({
        "decision": args.decision,
        "responder": "agentfence-cli",
        "reason": args.reason
    });
    let value = local_daemon_json(
        &args.daemon,
        "POST",
        &format!("/approvals/{}/resolve", args.id),
        Some(body),
    )?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(ExitCode::SUCCESS)
}

fn policy_command(command: PolicyCommands) -> Result<ExitCode> {
    match command {
        PolicyCommands::Validate { path } => {
            load_policy(&path)?;
            println!("valid policy: {}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommands::Schema => {
            println!("{}", policy_schema_json()?);
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommands::Ask { instruction } => {
            let proposal = propose_policy_patch(&instruction.join(" "));
            println!("{}", serde_json::to_string_pretty(&proposal)?);
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommands::Apply {
            path,
            yes,
            instruction,
        } => {
            let prompt = instruction.join(" ");
            let proposal = propose_policy_patch(&prompt);
            println!("{}", serde_json::to_string_pretty(&proposal)?);
            if !yes
                && !prompt_for_approval(
                    "apply policy patch",
                    "policy changes require confirmation",
                )?
            {
                println!("policy patch was not applied");
                return Ok(ExitCode::from(13));
            }

            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read policy {}", path.display()))?;
            let mut value: serde_json::Value = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse policy {}", path.display()))?;
            apply_policy_patch(&mut value, &proposal.operations)?;
            fs::write(&path, serde_json::to_string_pretty(&value)?)
                .with_context(|| format!("failed to write policy {}", path.display()))?;
            println!("updated {}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommands::Bundle { command } => policy_bundle_command(command),
    }
}

fn policy_bundle_command(command: PolicyBundleCommands) -> Result<ExitCode> {
    match command {
        PolicyBundleCommands::Keygen { output } => {
            let keypair = generate_policy_bundle_keypair();
            fs::write(&output, serde_json::to_string_pretty(&keypair)?)
                .with_context(|| format!("failed to write keypair {}", output.display()))?;
            println!("created policy bundle keypair {}", output.display());
            Ok(ExitCode::SUCCESS)
        }
        PolicyBundleCommands::Export {
            policy,
            output,
            name,
            description,
            organization,
            key,
        } => {
            let policy = load_policy(&policy)?;
            let mut bundle = create_policy_bundle(name, description, organization, policy)?;
            if let Some(key) = key {
                let keypair = load_policy_bundle_keypair(&key)?;
                sign_policy_bundle(&mut bundle, &keypair)?;
            }
            fs::write(&output, serde_json::to_string_pretty(&bundle)?)
                .with_context(|| format!("failed to write bundle {}", output.display()))?;
            println!("created bundle {}", output.display());
            Ok(ExitCode::SUCCESS)
        }
        PolicyBundleCommands::Verify { path } => {
            let bundle = load_policy_bundle(&path)?;
            let verification = verify_policy_bundle(&bundle)?;
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(if verification.valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        PolicyBundleCommands::Sign { path, key, output } => {
            let mut bundle = load_policy_bundle(&path)?;
            let keypair = load_policy_bundle_keypair(&key)?;
            sign_policy_bundle(&mut bundle, &keypair)?;
            let output = output.unwrap_or(path);
            fs::write(&output, serde_json::to_string_pretty(&bundle)?)
                .with_context(|| format!("failed to write signed bundle {}", output.display()))?;
            println!("signed bundle {}", output.display());
            Ok(ExitCode::SUCCESS)
        }
        PolicyBundleCommands::Import {
            path,
            output,
            yes,
            require_signature,
        } => {
            let bundle = load_policy_bundle(&path)?;
            let verification = verify_policy_bundle(&bundle)?;
            if !verification.valid {
                bail!(
                    "bundle verification failed: expected {}, actual {}",
                    verification.expected_digest,
                    verification.actual_digest
                );
            }
            if require_signature && verification.signature_valid != Some(true) {
                bail!("bundle import requires a valid signature");
            }
            if !yes
                && !prompt_for_approval(
                    "import policy bundle",
                    "bundle import replaces the output policy",
                )?
            {
                println!("policy bundle was not imported");
                return Ok(ExitCode::from(13));
            }
            save_policy(&output, &bundle.policy)?;
            println!("imported bundle {} to {}", path.display(), output.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load_policy_bundle(path: &Path) -> Result<PolicyBundle> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy bundle {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy bundle {}", path.display()))
}

fn load_policy_bundle_keypair(path: &Path) -> Result<PolicyBundleKeyPair> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy bundle keypair {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy bundle keypair {}", path.display()))
}

fn filesystem_command(command: FilesystemCommands) -> Result<ExitCode> {
    match command {
        FilesystemCommands::Check {
            operation,
            path,
            policy,
        } => {
            let cwd = env::current_dir().context("failed to read current directory")?;
            let policy_path = resolve_policy_path(policy.as_deref(), &cwd)?;
            let policy = load_policy(&policy_path)?;
            let result = evaluate_filesystem(&policy, &FilesystemRequest { operation, path });
            print_decision(&result);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn network_command(command: NetworkCommands) -> Result<ExitCode> {
    match command {
        NetworkCommands::Check { domain, policy } => {
            let cwd = env::current_dir().context("failed to read current directory")?;
            let policy_path = resolve_policy_path(policy.as_deref(), &cwd)?;
            let policy = load_policy(&policy_path)?;
            let result = evaluate_network(&policy, &NetworkRequest { domain });
            print_decision(&result);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn skill_command(command: SkillCommands) -> Result<ExitCode> {
    match command {
        SkillCommands::Check { name, policy } => {
            let cwd = env::current_dir().context("failed to read current directory")?;
            let policy_path = resolve_policy_path(policy.as_deref(), &cwd)?;
            let policy = load_policy(&policy_path)?;
            let result = evaluate_skill(&policy, &SkillRequest { skill: name });
            print_decision(&result);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn mcp_command(command: McpCommands) -> Result<ExitCode> {
    match command {
        McpCommands::Check {
            server,
            kind,
            name,
            policy,
        } => {
            let cwd = env::current_dir().context("failed to read current directory")?;
            let policy_path = resolve_policy_path(policy.as_deref(), &cwd)?;
            let policy = load_policy(&policy_path)?;
            let decision = agentfence_mcp::decide(
                &policy,
                agentfence_mcp::McpAccessRequest {
                    server,
                    kind,
                    name,
                    arguments: serde_json::Value::Null,
                },
            );
            println!("{}", serde_json::to_string_pretty(&decision)?);
            Ok(ExitCode::SUCCESS)
        }
        McpCommands::Proxy(args) => mcp_proxy(args),
    }
}

fn mcp_proxy(args: McpProxyArgs) -> Result<ExitCode> {
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = resolve_policy_path(args.policy.as_deref(), &cwd)?;
    let policy = load_policy(&policy_path)?;
    let policy_for_upstream = policy.clone();
    let server_for_upstream = args.server.clone();
    let mut rate_limiter = agentfence_mcp::McpRateLimiter::for_server(&policy, &args.server);

    let mut child = Command::new(&args.command[0])
        .args(&args.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start upstream MCP server {}", args.command[0]))?;

    let mut upstream_stdin = child
        .stdin
        .take()
        .context("failed to open upstream MCP stdin")?;
    let upstream_stdout = child
        .stdout
        .take()
        .context("failed to open upstream MCP stdout")?;

    let shared_stdout = Arc::new(Mutex::new(io::stdout()));
    let pending_list_requests = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let upstream_stdout_writer = Arc::clone(&shared_stdout);
    let upstream_pending = Arc::clone(&pending_list_requests);
    let upstream_to_client = thread::spawn(move || -> Result<()> {
        let mut reader = BufReader::new(upstream_stdout);
        while let Some(frame) = agentfence_mcp::read_frame(&mut reader)? {
            let frame = match agentfence_mcp::decode_frame_json(&frame) {
                Ok(message) => {
                    if let Some(id) = agentfence_mcp::message_id_key(&message) {
                        let method = upstream_pending
                            .lock()
                            .map_err(|_| anyhow::anyhow!("MCP request map lock poisoned"))?
                            .remove(&id);
                        if let Some(method) = method {
                            let filtered = agentfence_mcp::filter_list_response(
                                &policy_for_upstream,
                                &server_for_upstream,
                                &method,
                                &message,
                            );
                            if filtered.removed > 0 {
                                eprintln!(
                                    "agentfence mcp proxy: filtered {} item(s) from {}",
                                    filtered.removed, method
                                );
                            }
                            agentfence_mcp::frame_from_json(frame.kind, &filtered.response)?
                        } else {
                            frame
                        }
                    } else {
                        frame
                    }
                }
                Err(_) => frame,
            };
            let mut stdout = upstream_stdout_writer
                .lock()
                .map_err(|_| anyhow::anyhow!("stdout lock poisoned"))?;
            agentfence_mcp::write_frame(&mut *stdout, &frame)?;
        }
        Ok(())
    });

    let stdin = io::stdin();
    let mut client_reader = BufReader::new(stdin.lock());

    while let Some(frame) = agentfence_mcp::read_frame(&mut client_reader)? {
        let message = match agentfence_mcp::decode_frame_json(&frame) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("agentfence mcp proxy: forwarding unparsed frame: {error}");
                agentfence_mcp::write_frame(&mut upstream_stdin, &frame)?;
                continue;
            }
        };

        let Some(request) = agentfence_mcp::inspect_client_message(&args.server, &message) else {
            if let (Some(method), Some(id)) = (
                agentfence_mcp::list_method(&message),
                agentfence_mcp::message_id_key(&message),
            ) {
                pending_list_requests
                    .lock()
                    .map_err(|_| anyhow::anyhow!("MCP request map lock poisoned"))?
                    .insert(id, method.to_string());
            }
            agentfence_mcp::write_frame(&mut upstream_stdin, &frame)?;
            continue;
        };

        let decision = agentfence_mcp::decide(&policy, request);
        let allowed = match decision.decision.decision {
            Decision::Allow
            | Decision::AllowOnce
            | Decision::AllowForSession
            | Decision::AllowWithConstraints => true,
            Decision::Ask => matches!(args.ask_mode, McpAskMode::Allow),
            Decision::Deny => false,
        };
        let allowed = if decision.decision.decision == Decision::Ask
            && matches!(args.ask_mode, McpAskMode::Queue)
        {
            wait_for_mcp_approval(
                &args.daemon,
                args.ask_timeout_seconds,
                &decision.request.server,
                &decision.request.kind,
                &decision.request.name,
                decision.request.arguments.clone(),
                decision.decision.clone(),
            )?
        } else {
            allowed
        };
        let mut denial_decision = decision.decision.clone();
        let allowed = if allowed {
            if let Some(rate_limit_decision) = rate_limiter.check(&decision.request) {
                denial_decision = rate_limit_decision;
                false
            } else {
                true
            }
        } else {
            false
        };

        if allowed {
            agentfence_mcp::write_frame(&mut upstream_stdin, &frame)?;
        } else {
            let response = agentfence_mcp::error_response(
                &message,
                -32001,
                format!(
                    "AgentFence denied MCP {} {}/{}: {}",
                    decision.request.kind,
                    decision.request.server,
                    decision.request.name,
                    denial_decision.reason
                ),
            );
            let response_frame = agentfence_mcp::frame_from_json(frame.kind, &response)?;
            let mut client_stdout = shared_stdout
                .lock()
                .map_err(|_| anyhow::anyhow!("stdout lock poisoned"))?;
            agentfence_mcp::write_frame(&mut *client_stdout, &response_frame)?;
        }
    }

    drop(upstream_stdin);
    let status = child
        .wait()
        .context("failed to wait for upstream MCP server")?;
    upstream_to_client
        .join()
        .map_err(|_| anyhow::anyhow!("upstream MCP forwarding thread panicked"))?
        .context("failed to forward upstream MCP output")?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn print_decision(result: &agentfence_policy::DecisionResult) {
    println!("decision: {:?}", result.decision);
    println!("risk: {:?}", result.risk);
    println!("reason: {}", result.reason);
    if let Some(rule) = &result.matched_rule {
        println!("matchedRule: {rule}");
    }
}

fn approve_network_decisions(decisions: &[(String, DecisionResult)]) -> Result<bool> {
    for (domain, decision) in decisions {
        match decision.decision {
            Decision::Allow
            | Decision::AllowOnce
            | Decision::AllowForSession
            | Decision::AllowWithConstraints => {}
            Decision::Deny => {
                println!("denied network domain: {domain}");
                return Ok(false);
            }
            Decision::Ask => {
                let subject = format!("network access to {domain}");
                if !prompt_for_approval(&subject, &decision.reason)? {
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

fn combined_shell_network_reason(
    shell: &DecisionResult,
    network: &[(String, DecisionResult)],
) -> String {
    let mut reasons = vec![format!("shell: {}", shell.reason)];
    reasons.extend(
        network
            .iter()
            .map(|(domain, decision)| format!("network {domain}: {}", decision.reason)),
    );
    reasons.join("; ")
}

fn effective_decision_from_json(
    shell: &DecisionResult,
    network: &[serde_json::Value],
) -> DecisionResult {
    if shell.decision == Decision::Deny {
        return shell.clone();
    }

    if let Some((domain, decision)) = network.iter().find_map(network_decision_from_json) {
        if decision.decision == Decision::Deny {
            let mut decision = decision.clone();
            decision.reason = format!("network {domain}: {}", decision.reason);
            return decision;
        }
    }

    if shell.decision == Decision::Ask {
        return shell.clone();
    }

    if let Some((domain, decision)) = network.iter().find_map(|value| {
        let (domain, decision) = network_decision_from_json(value)?;
        (decision.decision == Decision::Ask).then_some((domain, decision))
    }) {
        let mut decision = decision.clone();
        decision.reason = format!("network {domain}: {}", decision.reason);
        return decision;
    }

    shell.clone()
}

fn explain_simulation_json(
    shell: &DecisionResult,
    network: &[serde_json::Value],
    decision: &DecisionResult,
) -> Vec<String> {
    let mut explanation = vec![format!("shell {:?}: {}", shell.decision, shell.reason)];
    for value in network {
        if let Some((domain, decision)) = network_decision_from_json(value) {
            explanation.push(format!(
                "network {domain} {:?}: {}",
                decision.decision, decision.reason
            ));
        }
    }
    explanation.push(format!(
        "effective {:?}: {}",
        decision.decision, decision.reason
    ));
    explanation
}

fn network_decision_from_json(value: &serde_json::Value) -> Option<(&str, DecisionResult)> {
    let domain = value.get("domain")?.as_str()?;
    let decision = serde_json::from_value::<DecisionResult>(value.get("decision")?.clone()).ok()?;
    Some((domain, decision))
}

fn wait_for_mcp_approval(
    daemon: &str,
    timeout_seconds: u64,
    server: &str,
    kind: &str,
    name: &str,
    arguments: serde_json::Value,
    decision: agentfence_policy::DecisionResult,
) -> Result<bool> {
    let create = serde_json::json!({
        "actor": "mcp-proxy",
        "action": format!("mcp.{kind}"),
        "subject": format!("{server}/{name}"),
        "decision": decision,
        "metadata": {
            "server": server,
            "kind": kind,
            "name": name,
            "arguments": arguments
        }
    });
    let approval = local_daemon_json(daemon, "POST", "/approvals", Some(create))?;
    let id = approval
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("daemon approval response did not include id")?;

    eprintln!("agentfence mcp proxy: waiting for approval {id}");
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    loop {
        let current = local_daemon_json(daemon, "GET", &format!("/approvals/{id}"), None)?;
        let status = current
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("expired");
        match status {
            "allowed" => return Ok(true),
            "denied" | "expired" => return Ok(false),
            _ if Instant::now() >= deadline => return Ok(false),
            _ => thread::sleep(Duration::from_millis(500)),
        }
    }
}

fn resolve_policy_path(explicit: Option<&Path>, cwd: &Path) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    discover_policy(cwd).or_else(|_| Ok(cwd.join("agentfence.policy.json")))
}

fn prompt_for_approval(command: &str, reason: &str) -> Result<bool> {
    println!("AgentFence approval required");
    println!("command: {command}");
    println!("reason: {reason}");
    print!("allow once? [y/N] ");
    io::stdout().flush().context("failed to flush stdout")?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read approval response")?;
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn local_daemon_json(
    base: &str,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let authority = base
        .strip_prefix("http://")
        .unwrap_or(base)
        .trim_end_matches('/');
    let mut stream = TcpStream::connect(authority)
        .with_context(|| format!("failed to connect to daemon at {authority}"))?;
    let body_raw = body
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("failed to encode daemon request")?
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_raw.len(),
        body_raw
    );
    stream
        .write_all(request.as_bytes())
        .context("failed to write daemon request")?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("failed to read daemon response")?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("invalid daemon HTTP response")?;
    if !head.contains(" 200 ") {
        bail!("daemon returned non-200 response: {head}");
    }
    serde_json::from_str(body).context("failed to parse daemon JSON response")
}
