use std::collections::{BTreeMap, HashMap};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use agentfence_audit::{AuditEvent, AuditExportFormat, AuditStore};
use agentfence_policy::{
    ActorPolicy, Decision, DecisionResult, FilesystemRequest, McpServerPolicy, NetworkRequest,
    Policy, PolicyBundle, PolicyBundleKeyPair, PolicyObservation, PolicyPreset, RateLimitPolicy,
    ShellMatch, ShellRequest, ShellRule, SkillRequest, apply_policy_patch, create_policy_bundle,
    discover_policy, evaluate_filesystem, evaluate_network, evaluate_shell, evaluate_skill,
    generate_policy_bundle_keypair, load_policy, policy_schema_json, preset_policy,
    propose_policy_patch, save_policy, sign_policy_bundle, suggest_policy_patches,
    verify_policy_bundle,
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
    Shell(ShellArgs),
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
    Integrations {
        #[command(subcommand)]
        command: IntegrationCommands,
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
struct ShellArgs {
    #[arg(long, default_value = "codex")]
    actor: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
    #[arg(long, default_value = "agentfence> ")]
    prompt: String,
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
    Report {
        #[arg(long, default_value = "json")]
        format: AuditReportFormat,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AuditReportFormat {
    Json,
    Markdown,
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
    Suggest {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        audit: Option<PathBuf>,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        #[arg(long, default_value_t = 3)]
        threshold: usize,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Template {
        #[command(subcommand)]
        command: PolicyTemplateCommands,
    },
    Bundle {
        #[command(subcommand)]
        command: PolicyBundleCommands,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyTemplateCommands {
    List,
    Show {
        template: PolicyTemplate,
    },
    Export {
        template: PolicyTemplate,
        #[arg(long, default_value = "agentfence.policy.json")]
        output: PathBuf,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PolicyTemplate {
    EngineeringDefault,
    ReadOnlyAudit,
    ReleaseGuard,
}

#[derive(Debug, Clone, Copy)]
struct PolicyTemplateSpec {
    slug: &'static str,
    title: &'static str,
    description: &'static str,
    preset: PolicyPreset,
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
enum IntegrationCommands {
    List,
    Show {
        profile: IntegrationProfile,
        #[arg(long, default_value = "json")]
        format: IntegrationFormat,
    },
    Install {
        profile: IntegrationProfile,
        #[arg(long, default_value = ".agentfence/wrappers")]
        output_dir: PathBuf,
        #[arg(long, default_value = "shell")]
        format: IntegrationFormat,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        add_to_path: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum IntegrationProfile {
    Codex,
    ClaudeCode,
    CursorStyle,
    GenericMcp,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum IntegrationFormat {
    Json,
    Shell,
    #[value(name = "powershell")]
    PowerShell,
}

#[derive(Debug, Clone, Copy)]
struct IntegrationProfileSpec {
    slug: &'static str,
    agent: &'static str,
    actor: &'static str,
    recommended_preset: &'static str,
    init_project: Option<&'static str>,
    policy: Option<&'static str>,
    command: &'static [&'static str],
    audit_store: Option<&'static str>,
    daemon: Option<&'static str>,
    notes: &'static [&'static str],
}

const CODEX_COMMAND: &[&str] = &["agentfence", "run", "--actor", "codex", "--", "codex"];
const CLAUDE_CODE_COMMAND: &[&str] = &[
    "agentfence",
    "run",
    "--actor",
    "claude-code",
    "--",
    "claude",
];
const CURSOR_STYLE_COMMAND: &[&str] = &[
    "agentfence",
    "run",
    "--actor",
    "cursor-agent",
    "--",
    "node",
    "./agent-entrypoint.js",
];
const GENERIC_MCP_COMMAND: &[&str] = &[
    "agentfence",
    "mcp",
    "proxy",
    "--server",
    "github",
    "--ask-mode",
    "queue",
    "--",
    "node",
    "path/to/github-mcp-server.js",
];

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
    HttpProxy(McpHttpProxyArgs),
}

#[derive(Debug, Args)]
struct McpProxyArgs {
    #[arg(long)]
    server: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
    #[arg(long, default_value = "deny")]
    ask_mode: McpAskMode,
    #[arg(long, default_value = "http://127.0.0.1:37421")]
    daemon: String,
    #[arg(long, default_value_t = 900)]
    ask_timeout_seconds: u64,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args, Clone)]
struct McpHttpProxyArgs {
    #[arg(long)]
    server: String,
    #[arg(long, default_value = "127.0.0.1:37422")]
    listen: SocketAddr,
    #[arg(long)]
    upstream: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
    #[arg(long, default_value = "deny")]
    ask_mode: McpAskMode,
    #[arg(long, default_value = "http://127.0.0.1:37421")]
    daemon: String,
    #[arg(long, default_value_t = 900)]
    ask_timeout_seconds: u64,
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
        Commands::Shell(args) => guarded_shell(args),
        Commands::Check(args) => check(args),
        Commands::Logs(args) => logs(args),
        Commands::Audit { command } => audit_command(command),
        Commands::Approvals { command } => approvals_command(command),
        Commands::Approve(args) => approve(args),
        Commands::Filesystem { command } => filesystem_command(command),
        Commands::Network { command } => network_command(command),
        Commands::Skill { command } => skill_command(command),
        Commands::Integrations { command } => integrations_command(command),
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
    run_guarded_command(
        &args.actor,
        args.policy.as_deref(),
        args.audit.as_deref(),
        &args.command,
    )
}

fn run_guarded_command(
    actor: &str,
    policy_path: Option<&Path>,
    audit_path: Option<&Path>,
    command_args: &[String],
) -> Result<ExitCode> {
    let outcome = guard_shell_command(actor, policy_path, audit_path, command_args)?;
    if !outcome.allowed {
        println!("denied: {}", outcome.command);
        return Ok(ExitCode::from(13));
    }

    let status = Command::new(&command_args[0])
        .args(&command_args[1..])
        .status()
        .with_context(|| format!("failed to execute {}", command_args[0]))?;

    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

struct GuardedShellOutcome {
    allowed: bool,
    command: String,
}

fn guard_shell_command(
    actor: &str,
    policy_path: Option<&Path>,
    audit_path: Option<&Path>,
    command_args: &[String],
) -> Result<GuardedShellOutcome> {
    if command_args.is_empty() {
        bail!("command is empty");
    }

    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = resolve_policy_path(policy_path, &cwd)?;
    let policy = load_policy(&policy_path)?;
    let command = classify_command(command_args);
    let request = ShellRequest {
        actor: actor.to_string(),
        command: command.command_line.clone(),
        args: command_args.to_vec(),
        cwd: cwd.display().to_string(),
        risk: command.risk,
    };
    let result = evaluate_shell(&policy, &request);
    let network_decisions = extract_network_domains(command_args)
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
        actor,
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
        let audit_path = audit_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(&policy.audit.store));
        AuditStore::open(audit_path)?.append(&event)?;
    }

    Ok(GuardedShellOutcome {
        allowed,
        command: request.command,
    })
}

fn guarded_shell(args: ShellArgs) -> Result<ExitCode> {
    let stdin = io::stdin();
    let mut input = String::new();
    println!("AgentFence guarded shell. Type exit or quit to leave.");

    loop {
        print!("{}", args.prompt);
        io::stdout().flush().context("failed to flush prompt")?;
        input.clear();
        if stdin
            .read_line(&mut input)
            .context("failed to read shell input")?
            == 0
        {
            println!();
            break;
        }

        let line = input.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line, "exit" | "quit") {
            break;
        }

        let command = match parse_shell_line(line) {
            Ok(command) => command,
            Err(error) => {
                eprintln!("parse error: {error}");
                continue;
            }
        };
        if command.is_empty() {
            continue;
        }

        let outcome = guard_shell_command(
            &args.actor,
            args.policy.as_deref(),
            args.audit.as_deref(),
            &command,
        )?;
        if !outcome.allowed {
            println!("denied: {}", outcome.command);
            continue;
        }

        if is_cd_command(&command) {
            if let Err(error) = change_directory(&command) {
                eprintln!("cd: {error}");
            }
            continue;
        }

        let status = Command::new(&command[0])
            .args(&command[1..])
            .status()
            .with_context(|| format!("failed to execute {}", command[0]))?;
        if !status.success() {
            eprintln!(
                "command exited with {}",
                status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "unknown status".to_string())
            );
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn parse_shell_line(input: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }

        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }

        if let Some(quote_character) = quote {
            if character == quote_character {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }

        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character.is_whitespace() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }

    if escaped {
        current.push('\\');
    }
    if quote.is_some() {
        bail!("unterminated quote");
    }
    if !current.is_empty() {
        args.push(current);
    }

    Ok(args)
}

fn is_cd_command(command: &[String]) -> bool {
    command
        .first()
        .is_some_and(|value| value.eq_ignore_ascii_case("cd"))
}

fn change_directory(command: &[String]) -> Result<()> {
    let target = if let Some(path) = command.get(1) {
        PathBuf::from(path)
    } else {
        home_dir().context("failed to find home directory")?
    };
    env::set_current_dir(&target)
        .with_context(|| format!("failed to change directory to {}", target.display()))
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
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
        AuditCommands::Report {
            format,
            limit,
            output,
            audit,
        } => {
            let path = audit.unwrap_or_else(|| PathBuf::from(".agentfence/audit.sqlite"));
            let store = AuditStore::open(path)?;
            let events = store.list_recent(limit)?;
            let report = match format {
                AuditReportFormat::Json => {
                    serde_json::to_string_pretty(&audit_report_json(&events, limit))?
                }
                AuditReportFormat::Markdown => audit_report_markdown(&events, limit),
            };
            if let Some(output) = output {
                fs::write(&output, report).with_context(|| {
                    format!("failed to write audit report {}", output.display())
                })?;
                println!("created audit report {}", output.display());
            } else {
                println!("{report}");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn audit_report_json(events: &[AuditEvent], limit: usize) -> serde_json::Value {
    serde_json::json!({
        "limit": limit,
        "totalEvents": events.len(),
        "newestEventAt": events.first().map(|event| event.timestamp.to_rfc3339()),
        "oldestEventAt": events.last().map(|event| event.timestamp.to_rfc3339()),
        "decisions": count_by(events, |event| &event.decision),
        "risks": count_by(events, |event| &event.risk),
        "actors": count_by(events, |event| &event.actor),
        "actions": count_by(events, |event| &event.action),
        "reviewEvents": events
            .iter()
            .filter(|event| event.decision == "deny" || event.decision == "ask")
            .take(20)
            .map(|event| serde_json::json!({
                "timestamp": event.timestamp.to_rfc3339(),
                "actor": event.actor,
                "action": event.action,
                "decision": event.decision,
                "risk": event.risk,
                "subject": event.subject,
                "reason": event.reason,
                "matchedRule": event.matched_rule
            }))
            .collect::<Vec<_>>()
    })
}

fn audit_report_markdown(events: &[AuditEvent], limit: usize) -> String {
    let mut output = String::new();
    output.push_str("# AgentFence Audit Report\n\n");
    output.push_str(&format!("- Limit: {limit}\n"));
    output.push_str(&format!("- Total events: {}\n", events.len()));
    output.push_str(&format!(
        "- Newest event: {}\n",
        events
            .first()
            .map(|event| event.timestamp.to_rfc3339())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    output.push_str(&format!(
        "- Oldest event: {}\n\n",
        events
            .last()
            .map(|event| event.timestamp.to_rfc3339())
            .unwrap_or_else(|| "n/a".to_string())
    ));

    output.push_str("## Decisions\n\n");
    output.push_str(&count_table(
        "Decision",
        &count_by(events, |event| &event.decision),
    ));
    output.push_str("\n## Risks\n\n");
    output.push_str(&count_table("Risk", &count_by(events, |event| &event.risk)));
    output.push_str("\n## Actors\n\n");
    output.push_str(&count_table(
        "Actor",
        &count_by(events, |event| &event.actor),
    ));
    output.push_str("\n## Actions\n\n");
    output.push_str(&count_table(
        "Action",
        &count_by(events, |event| &event.action),
    ));

    output.push_str("\n## Review Events\n\n");
    let review_events = events
        .iter()
        .filter(|event| event.decision == "deny" || event.decision == "ask")
        .take(20)
        .collect::<Vec<_>>();
    if review_events.is_empty() {
        output.push_str("No deny or ask events in the selected window.\n");
    } else {
        output.push_str("| Time | Actor | Decision | Risk | Action | Subject |\n");
        output.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for event in review_events {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                event.timestamp.to_rfc3339(),
                escape_markdown_table(&event.actor),
                escape_markdown_table(&event.decision),
                escape_markdown_table(&event.risk),
                escape_markdown_table(&event.action),
                escape_markdown_table(&event.subject)
            ));
        }
    }

    output
}

fn count_by<'a>(
    events: &'a [AuditEvent],
    key: impl Fn(&'a AuditEvent) -> &'a str,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for event in events {
        *counts.entry(key(event).to_string()).or_insert(0) += 1;
    }
    counts
}

fn count_table(label: &str, counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "No events.\n".to_string();
    }

    let mut output = format!("| {label} | Count |\n| --- | ---: |\n");
    for (key, count) in counts {
        output.push_str(&format!("| {} | {count} |\n", escape_markdown_table(key)));
    }
    output
}

fn escape_markdown_table(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
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
        PolicyCommands::Suggest {
            policy,
            audit,
            limit,
            threshold,
            output,
        } => {
            let cwd = env::current_dir().context("failed to read current directory")?;
            let policy_path = resolve_policy_path(policy.as_deref(), &cwd)?;
            let policy = load_policy(&policy_path)?;
            let audit_path = audit.unwrap_or_else(|| PathBuf::from(&policy.audit.store));
            let store = AuditStore::open(&audit_path)?;
            let events = store.list_recent(limit)?;
            let observations = policy_observations_from_audit(&events);
            let report = suggest_policy_patches(&policy, &observations, threshold);
            let output_json = serde_json::to_string_pretty(&report)?;
            if let Some(output) = output {
                fs::write(&output, output_json).with_context(|| {
                    format!("failed to write policy suggestions {}", output.display())
                })?;
                println!("created policy suggestions {}", output.display());
            } else {
                println!("{output_json}");
            }
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommands::Template { command } => policy_template_command(command),
        PolicyCommands::Bundle { command } => policy_bundle_command(command),
    }
}

fn policy_observations_from_audit(events: &[AuditEvent]) -> Vec<PolicyObservation> {
    events
        .iter()
        .map(|event| PolicyObservation {
            actor: event.actor.clone(),
            action: event.action.clone(),
            subject: event.subject.clone(),
            decision: event.decision.clone(),
            risk: event.risk.clone(),
            reason: event.reason.clone(),
            matched_rule: event.matched_rule.clone(),
            metadata: event.metadata.clone(),
        })
        .collect()
}

fn policy_template_command(command: PolicyTemplateCommands) -> Result<ExitCode> {
    match command {
        PolicyTemplateCommands::List => {
            for template in [
                PolicyTemplate::EngineeringDefault,
                PolicyTemplate::ReadOnlyAudit,
                PolicyTemplate::ReleaseGuard,
            ] {
                let spec = policy_template_spec(template);
                println!(
                    "{:<20} preset={:<16} {}",
                    spec.slug,
                    policy_preset_name(spec.preset),
                    spec.description
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        PolicyTemplateCommands::Show { template } => {
            let spec = policy_template_spec(template);
            let policy = build_policy_template(template, None);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "template": spec.slug,
                    "title": spec.title,
                    "description": spec.description,
                    "preset": policy_preset_name(spec.preset),
                    "policy": policy
                }))?
            );
            Ok(ExitCode::SUCCESS)
        }
        PolicyTemplateCommands::Export {
            template,
            output,
            project,
            force,
        } => {
            if output.exists() && !force {
                bail!(
                    "{} already exists; rerun with --force to replace it",
                    output.display()
                );
            }
            let policy = build_policy_template(template, project);
            save_policy(&output, &policy)?;
            println!("created policy template {}", output.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn policy_template_spec(template: PolicyTemplate) -> PolicyTemplateSpec {
    match template {
        PolicyTemplate::EngineeringDefault => PolicyTemplateSpec {
            slug: "engineering-default",
            title: "Engineering Default",
            description: "Balanced local development policy for coding agents.",
            preset: PolicyPreset::Developer,
        },
        PolicyTemplate::ReadOnlyAudit => PolicyTemplateSpec {
            slug: "read-only-audit",
            title: "Read-Only Audit",
            description: "Read-only policy with strict writes and auditable inspection.",
            preset: PolicyPreset::ReadOnly,
        },
        PolicyTemplate::ReleaseGuard => PolicyTemplateSpec {
            slug: "release-guard",
            title: "Release Guard",
            description: "Stricter policy for release branches and production-sensitive work.",
            preset: PolicyPreset::Strict,
        },
    }
}

fn build_policy_template(template: PolicyTemplate, project: Option<String>) -> Policy {
    let spec = policy_template_spec(template);
    let mut policy = preset_policy(spec.preset, project.or_else(|| Some(spec.slug.to_string())));
    policy.actors.insert("codex".to_string(), actor("standard"));
    policy
        .actors
        .insert("claude-code".to_string(), actor("standard"));

    match template {
        PolicyTemplate::EngineeringDefault => {
            policy.shell.rules.push(ShellRule {
                id: "ask-git-history-rewrite".to_string(),
                description: Some("Ask before rewriting repository history.".to_string()),
                r#match: ShellMatch {
                    commands: vec![
                        "git reset".to_string(),
                        "git clean".to_string(),
                        "git push --force".to_string(),
                    ],
                    patterns: Vec::new(),
                    risks: Vec::new(),
                },
                decision: Decision::Ask,
                reason: Some("repository history changes require review".to_string()),
            });
            configure_github_mcp(&mut policy, Decision::Ask);
        }
        PolicyTemplate::ReadOnlyAudit => {
            policy.default_decision = Decision::Deny;
            policy.audit.enabled = true;
            policy.approval.remember_choices = false;
            configure_github_mcp(&mut policy, Decision::Deny);
        }
        PolicyTemplate::ReleaseGuard => {
            policy.default_decision = Decision::Ask;
            policy.network.default_decision = Decision::Deny;
            policy.skills.deny.push("release-publish".to_string());
            policy.shell.rules.push(ShellRule {
                id: "deny-release-publish".to_string(),
                description: Some("Deny direct release publishing commands.".to_string()),
                r#match: ShellMatch {
                    commands: Vec::new(),
                    patterns: vec![
                        "npm publish".to_string(),
                        "cargo publish".to_string(),
                        "gh release create".to_string(),
                        "docker push".to_string(),
                    ],
                    risks: Vec::new(),
                },
                decision: Decision::Deny,
                reason: Some("release publishing requires an out-of-band process".to_string()),
            });
            configure_github_mcp(&mut policy, Decision::Deny);
        }
    }

    policy
}

fn configure_github_mcp(policy: &mut Policy, default_decision: Decision) {
    let mut server = McpServerPolicy {
        decision: default_decision,
        rate_limit: RateLimitPolicy {
            enabled: true,
            max_requests: 60,
            window_seconds: 60,
        },
        ..McpServerPolicy::default()
    };
    server
        .tools
        .insert("list_pull_requests".to_string(), Decision::Allow);
    server
        .tools
        .insert("create_pull_request".to_string(), Decision::Ask);
    server
        .tools
        .insert("merge_pull_request".to_string(), Decision::Deny);
    server
        .tools
        .insert("create_release".to_string(), Decision::Deny);
    policy.mcp.servers.insert("github".to_string(), server);
}

fn actor(trust_level: &str) -> ActorPolicy {
    ActorPolicy {
        trust_level: Some(trust_level.to_string()),
    }
}

fn policy_preset_name(preset: PolicyPreset) -> &'static str {
    match preset {
        PolicyPreset::ReadOnly => "read-only",
        PolicyPreset::Developer => "developer",
        PolicyPreset::Strict => "strict",
        PolicyPreset::TrustedProject => "trusted-project",
        PolicyPreset::CiLike => "ci-like",
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

fn integrations_command(command: IntegrationCommands) -> Result<ExitCode> {
    match command {
        IntegrationCommands::List => {
            for profile in [
                IntegrationProfile::Codex,
                IntegrationProfile::ClaudeCode,
                IntegrationProfile::CursorStyle,
                IntegrationProfile::GenericMcp,
            ] {
                let spec = integration_profile_spec(profile);
                println!(
                    "{:<14} actor={:<14} preset={:<10} command={}",
                    spec.slug,
                    spec.actor,
                    spec.recommended_preset,
                    quote_command(spec.command, IntegrationFormat::Shell)
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        IntegrationCommands::Show { profile, format } => {
            let spec = integration_profile_spec(profile);
            match format {
                IntegrationFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&integration_json(spec))?);
                }
                IntegrationFormat::Shell | IntegrationFormat::PowerShell => {
                    println!("{}", integration_script(spec, format)?);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        IntegrationCommands::Install {
            profile,
            output_dir,
            format,
            force,
            add_to_path,
        } => {
            if matches!(format, IntegrationFormat::Json) {
                bail!("integration install requires --format shell or --format powershell");
            }
            let spec = integration_profile_spec(profile);
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("failed to create {}", output_dir.display()))?;
            let output = output_dir.join(integration_wrapper_filename(spec, format));
            if output.exists() && !force {
                bail!(
                    "{} already exists; rerun with --force to replace it",
                    output.display()
                );
            }
            fs::write(&output, integration_script(spec, format)?)
                .with_context(|| format!("failed to write wrapper {}", output.display()))?;
            make_wrapper_executable(&output)?;
            println!("created integration wrapper {}", output.display());
            if add_to_path {
                ensure_wrapper_dir_on_path(&output_dir)?;
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn integration_profile_spec(profile: IntegrationProfile) -> IntegrationProfileSpec {
    match profile {
        IntegrationProfile::Codex => IntegrationProfileSpec {
            slug: "codex",
            agent: "codex",
            actor: "codex",
            recommended_preset: "developer",
            init_project: Some("codex-project"),
            policy: Some("examples/codex.policy.json"),
            command: CODEX_COMMAND,
            audit_store: Some(".agentfence/audit.sqlite"),
            daemon: None,
            notes: &[
                "Run Codex through this wrapper to enforce shell and network-domain policy before execution.",
                "Use agentfence mcp proxy for MCP servers configured inside Codex.",
            ],
        },
        IntegrationProfile::ClaudeCode => IntegrationProfileSpec {
            slug: "claude-code",
            agent: "claude-code",
            actor: "claude-code",
            recommended_preset: "developer",
            init_project: Some("claude-code-project"),
            policy: Some("examples/claude-code.policy.json"),
            command: CLAUDE_CODE_COMMAND,
            audit_store: Some(".agentfence/audit.sqlite"),
            daemon: None,
            notes: &[
                "Replace the final command with the installed Claude Code binary if needed.",
                "Use daemon approvals when the desktop app is running.",
            ],
        },
        IntegrationProfile::CursorStyle => IntegrationProfileSpec {
            slug: "cursor-style",
            agent: "cursor-style-agent",
            actor: "cursor-agent",
            recommended_preset: "strict",
            init_project: Some("cursor-agent-project"),
            policy: None,
            command: CURSOR_STYLE_COMMAND,
            audit_store: Some(".agentfence/audit.sqlite"),
            daemon: None,
            notes: &[
                "Wrap the agent harness or script that actually launches local commands.",
                "Start strict, then loosen rules with explicit policy patches after observing audit logs.",
            ],
        },
        IntegrationProfile::GenericMcp => IntegrationProfileSpec {
            slug: "generic-mcp",
            agent: "generic-mcp-client",
            actor: "mcp-proxy",
            recommended_preset: "developer",
            init_project: None,
            policy: None,
            command: GENERIC_MCP_COMMAND,
            audit_store: None,
            daemon: Some("http://127.0.0.1:37421"),
            notes: &[
                "Use --ask-mode queue to route ask decisions to the daemon and desktop approval queue.",
                "Denied tools, resources, and prompts are blocked before they reach the upstream MCP server.",
            ],
        },
    }
}

fn integration_json(spec: IntegrationProfileSpec) -> serde_json::Value {
    let mut value = serde_json::json!({
        "profile": spec.slug,
        "agent": spec.agent,
        "actor": spec.actor,
        "recommendedPreset": spec.recommended_preset,
        "command": spec.command,
        "notes": spec.notes
    });

    if let Some(project) = spec.init_project {
        value["init"] = serde_json::json!({
            "command": ["agentfence", "init", "--preset", spec.recommended_preset, "--project", project]
        });
    }
    if let Some(policy) = spec.policy {
        value["policy"] = serde_json::json!(policy);
    }
    if let Some(audit_store) = spec.audit_store {
        value["auditStore"] = serde_json::json!(audit_store);
    }
    if let Some(daemon) = spec.daemon {
        value["daemon"] = serde_json::json!(daemon);
    }

    value
}

fn integration_script(spec: IntegrationProfileSpec, format: IntegrationFormat) -> Result<String> {
    if matches!(format, IntegrationFormat::Json) {
        bail!("JSON profiles cannot be rendered as wrapper scripts");
    }
    let comment = match format {
        IntegrationFormat::PowerShell => "#",
        IntegrationFormat::Shell | IntegrationFormat::Json => "#",
    };
    let mut output = String::new();
    if matches!(format, IntegrationFormat::Shell) {
        output.push_str("#!/usr/bin/env sh\nset -e\n");
    }
    output.push_str(&format!("{comment} AgentFence {} profile\n", spec.slug));
    output.push_str(&format!(
        "{comment} Recommended preset: {}\n",
        spec.recommended_preset
    ));
    if let Some(project) = spec.init_project {
        output.push_str(&format!("{comment} Run once:\n"));
        output.push_str(&format!(
            "{comment} {}\n",
            quote_command(
                &[
                    "agentfence",
                    "init",
                    "--preset",
                    spec.recommended_preset,
                    "--project",
                    project,
                ],
                format,
            )
        ));
    }

    let command = quote_command(spec.command, format);
    match format {
        IntegrationFormat::Shell => {
            output.push_str(&format!("exec {command} \"$@\"\n"));
        }
        IntegrationFormat::PowerShell => {
            output.push_str(
                "param([Parameter(ValueFromRemainingArguments = $true)][string[]]$AgentFenceArgs)\n",
            );
            output.push_str(&format!("& {command} @AgentFenceArgs\n"));
            output.push_str("exit $LASTEXITCODE\n");
        }
        IntegrationFormat::Json => unreachable!("checked above"),
    }
    Ok(output)
}

fn integration_wrapper_filename(spec: IntegrationProfileSpec, format: IntegrationFormat) -> String {
    match format {
        IntegrationFormat::PowerShell => format!("agentfence-{}.ps1", spec.slug),
        IntegrationFormat::Shell => format!("agentfence-{}", spec.slug),
        IntegrationFormat::Json => format!("agentfence-{}.json", spec.slug),
    }
}

fn make_wrapper_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)
            .with_context(|| format!("failed to stat wrapper {}", path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to mark wrapper executable {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn ensure_wrapper_dir_on_path(path: &Path) -> Result<()> {
    let directory = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve wrapper directory {}", path.display()))?;
    if path_env_contains_dir(&directory, env::var_os("PATH").as_deref()) {
        println!("wrapper directory already on PATH: {}", directory.display());
        return Ok(());
    }
    persist_path_dir(&directory)?;
    println!("added wrapper directory to PATH: {}", directory.display());
    println!("open a new terminal before invoking the wrapper by name");
    Ok(())
}

fn path_env_contains_dir(directory: &Path, path_env: Option<&OsStr>) -> bool {
    let Some(path_env) = path_env else {
        return false;
    };
    env::split_paths(path_env).any(|entry| paths_match_for_env(&entry, directory))
}

fn paths_match_for_env(left: &Path, right: &Path) -> bool {
    normalize_path_for_env(left) == normalize_path_for_env(right)
}

fn normalize_path_for_env(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('\\', "/");
    while value.len() > 1 && value.ends_with('/') {
        value.pop();
    }
    #[cfg(windows)]
    {
        value = value.to_ascii_lowercase();
    }
    value
}

#[cfg(windows)]
fn persist_path_dir(directory: &Path) -> Result<()> {
    let target = powershell_single_quote(&directory.to_string_lossy());
    let script = format!(
        "$target = {target}\n\
         $current = [Environment]::GetEnvironmentVariable('Path', 'User')\n\
         if ([string]::IsNullOrWhiteSpace($current)) {{ $parts = @() }} else {{ $parts = $current -split ';' | Where-Object {{ $_ -ne '' }} }}\n\
         if (-not ($parts | Where-Object {{ $_ -ieq $target }})) {{\n\
         $next = ($parts + $target) -join ';'\n\
         [Environment]::SetEnvironmentVariable('Path', $next, 'User')\n\
         }}\n"
    );
    let status = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(script)
        .status()
        .context("failed to update user PATH with powershell")?;
    if !status.success() {
        bail!("failed to update user PATH");
    }
    Ok(())
}

#[cfg(windows)]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(not(windows))]
fn persist_path_dir(directory: &Path) -> Result<()> {
    let home = env::var_os("HOME").context("HOME is not set; cannot update ~/.profile")?;
    let profile = PathBuf::from(home).join(".profile");
    let line = shell_path_export_line(directory);
    let existing = fs::read_to_string(&profile).unwrap_or_default();
    if !existing.contains(&directory.to_string_lossy().to_string()) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&profile)
            .with_context(|| format!("failed to update {}", profile.display()))?;
        writeln!(file, "\n# AgentFence wrapper path\n{line}")?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn shell_path_export_line(directory: &Path) -> String {
    format!(
        "export PATH={}:\"$PATH\"",
        shell_single_quote(&directory.to_string_lossy())
    )
}

#[cfg(not(windows))]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn quote_command(args: &[&str], format: IntegrationFormat) -> String {
    args.iter()
        .map(|arg| quote_arg(arg, format))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_arg(arg: &str, format: IntegrationFormat) -> String {
    if arg.is_empty()
        || arg
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '\'' | '"'))
    {
        match format {
            IntegrationFormat::PowerShell => format!("'{}'", arg.replace('\'', "''")),
            IntegrationFormat::Json | IntegrationFormat::Shell => {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        }
    } else {
        arg.to_string()
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
        McpCommands::HttpProxy(args) => mcp_http_proxy(args),
    }
}

#[derive(Debug, Clone)]
struct HttpUpstream {
    authority: String,
    connect_addr: String,
    path: String,
}

#[derive(Debug)]
struct SimpleHttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct SimpleHttpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
struct HttpListStreamFilter<'a> {
    policy: &'a Policy,
    server: &'a str,
    method: &'a str,
}

fn mcp_http_proxy(args: McpHttpProxyArgs) -> Result<ExitCode> {
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = resolve_policy_path(args.policy.as_deref(), &cwd)?;
    let policy = load_policy(&policy_path)?;
    let upstream = parse_http_upstream(&args.upstream)?;
    let listener = TcpListener::bind(args.listen)
        .with_context(|| format!("failed to bind MCP HTTP proxy {}", args.listen))?;
    let rate_limiter = Arc::new(Mutex::new(agentfence_mcp::McpRateLimiter::for_server(
        &policy,
        &args.server,
    )));
    let audit_path = if policy.audit.enabled {
        Some(
            args.audit
                .clone()
                .unwrap_or_else(|| PathBuf::from(&policy.audit.store)),
        )
    } else {
        None
    };
    let policy = Arc::new(policy);
    let upstream = Arc::new(upstream);
    let args = Arc::new(args);

    eprintln!(
        "agentfence mcp http-proxy: listening on http://{} and forwarding to {}",
        args.listen, args.upstream
    );

    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let args = Arc::clone(&args);
                let policy = Arc::clone(&policy);
                let upstream = Arc::clone(&upstream);
                let rate_limiter = Arc::clone(&rate_limiter);
                let audit_path = audit_path.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_mcp_http_connection(
                        &mut stream,
                        &args,
                        &policy,
                        &upstream,
                        &rate_limiter,
                        audit_path.as_deref(),
                    ) {
                        eprintln!("agentfence mcp http-proxy: {error:?}");
                        let body = serde_json::json!({
                            "error": "AgentFence MCP HTTP proxy failed",
                            "detail": error.to_string()
                        });
                        if let Ok(body) = serde_json::to_vec(&body) {
                            let _ =
                                write_http_response(&mut stream, 500, "application/json", &body);
                        }
                    }
                });
            }
            Err(error) => eprintln!("agentfence mcp http-proxy: connection failed: {error}"),
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn handle_mcp_http_connection(
    stream: &mut TcpStream,
    args: &McpHttpProxyArgs,
    policy: &agentfence_policy::Policy,
    upstream: &HttpUpstream,
    rate_limiter: &Arc<Mutex<agentfence_mcp::McpRateLimiter>>,
    audit_path: Option<&Path>,
) -> Result<()> {
    let request = read_http_request(stream)?;
    if request.method == "GET" {
        return forward_http_stream(upstream, &request, stream);
    }

    if request.method != "POST" {
        let body = serde_json::json!({
            "error": "AgentFence MCP HTTP proxy accepts POST JSON-RPC requests and GET streams"
        });
        return write_http_response(
            stream,
            405,
            "application/json",
            serde_json::to_string(&body)?.as_bytes(),
        );
    }

    let message = match serde_json::from_slice::<serde_json::Value>(&request.body) {
        Ok(message) => message,
        Err(error) => {
            let body = serde_json::json!({
                "error": "invalid JSON-RPC body",
                "detail": error.to_string()
            });
            return write_http_response(
                stream,
                400,
                "application/json",
                serde_json::to_string(&body)?.as_bytes(),
            );
        }
    };
    let list_method = agentfence_mcp::list_method(&message).map(str::to_string);

    if let Some(request_to_check) = agentfence_mcp::inspect_client_message(&args.server, &message) {
        let decision = agentfence_mcp::decide(policy, request_to_check);
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
            let mut limiter = rate_limiter
                .lock()
                .map_err(|_| anyhow::anyhow!("MCP HTTP rate limiter lock poisoned"))?;
            if let Some(rate_limit_decision) = limiter.check(&decision.request) {
                denial_decision = rate_limit_decision;
                false
            } else {
                true
            }
        } else {
            false
        };
        append_mcp_audit_for_path(
            audit_path,
            &decision.request,
            if allowed {
                &decision.decision
            } else {
                &denial_decision
            },
            allowed,
        )?;

        if !allowed {
            let body = agentfence_mcp::error_response(
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
            return write_http_response(
                stream,
                200,
                "application/json",
                serde_json::to_vec(&body)?.as_slice(),
            );
        }
    }

    let stream_filter = list_method.as_deref().map(|method| HttpListStreamFilter {
        policy,
        server: &args.server,
        method,
    });

    match forward_http_request(upstream, &request, stream, stream_filter)? {
        ForwardedHttpResponse::Complete(mut response) => {
            if let Some(method) = list_method {
                if let Ok(response_json) =
                    serde_json::from_slice::<serde_json::Value>(&response.body)
                {
                    let filtered = agentfence_mcp::filter_list_response(
                        policy,
                        &args.server,
                        &method,
                        &response_json,
                    );
                    if filtered.removed > 0 {
                        eprintln!(
                            "agentfence mcp http-proxy: filtered {} item(s) from {}",
                            filtered.removed, method
                        );
                    }
                    response.body = serde_json::to_vec(&filtered.response)?;
                    response.content_type = "application/json".to_string();
                }
            }

            write_http_response(
                stream,
                response.status,
                &response.content_type,
                &response.body,
            )
        }
        ForwardedHttpResponse::Streamed => Ok(()),
    }
}

fn parse_http_upstream(value: &str) -> Result<HttpUpstream> {
    let raw = value
        .strip_prefix("http://")
        .context("MCP HTTP proxy currently supports http:// upstream URLs only")?;
    let (authority, path) = match raw.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (raw, "/".to_string()),
    };
    if authority.is_empty() {
        bail!("upstream URL is missing a host");
    }
    let connect_addr = if authority.rsplit_once(':').is_some_and(|(_, port)| {
        !port.is_empty() && port.chars().all(|character| character.is_ascii_digit())
    }) {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    Ok(HttpUpstream {
        authority: authority.to_string(),
        connect_addr,
        path,
    })
}

fn read_http_request(stream: &TcpStream) -> Result<SimpleHttpRequest> {
    let mut reader = BufReader::new(stream.try_clone().context("failed to clone HTTP stream")?);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("failed to read HTTP request line")?;
    if request_line.trim().is_empty() {
        bail!("empty HTTP request");
    }
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .context("invalid HTTP request line")?
        .to_string();
    let path = request_parts.next().unwrap_or("/").to_string();

    let mut content_length = 0_usize;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("failed to read HTTP header")?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .context("invalid HTTP Content-Length")?;
            }
        }
    }

    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .context("failed to read HTTP body")?;
    }

    Ok(SimpleHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

enum ForwardedHttpResponse {
    Complete(SimpleHttpResponse),
    Streamed,
}

fn forward_http_stream(
    upstream: &HttpUpstream,
    request: &SimpleHttpRequest,
    client: &mut TcpStream,
) -> Result<()> {
    match forward_http_request(upstream, request, client, None)? {
        ForwardedHttpResponse::Complete(response) => write_http_response(
            client,
            response.status,
            &response.content_type,
            &response.body,
        ),
        ForwardedHttpResponse::Streamed => Ok(()),
    }
}

fn forward_http_request(
    upstream: &HttpUpstream,
    request: &SimpleHttpRequest,
    client: &mut TcpStream,
    stream_filter: Option<HttpListStreamFilter<'_>>,
) -> Result<ForwardedHttpResponse> {
    let mut stream = TcpStream::connect(&upstream.connect_addr)
        .with_context(|| format!("failed to connect to upstream {}", upstream.connect_addr))?;
    write_upstream_http_request(&mut stream, upstream, request)?;
    let mut reader = BufReader::new(stream);
    let (status, reason, headers) = read_http_response_head(&mut reader)?;

    if response_should_stream(&request.method, &headers) {
        if let Some(filter) = stream_filter {
            if response_is_event_stream(&headers) {
                write_http_filtered_stream_head(client, status, &reason, &headers)?;
                let removed = if response_is_chunked(&headers) {
                    let chunked = ChunkedBodyReader::new(reader);
                    let mut event_reader = BufReader::new(chunked);
                    filter_sse_list_stream(
                        &mut event_reader,
                        client,
                        filter.policy,
                        filter.server,
                        filter.method,
                    )?
                } else {
                    filter_sse_list_stream(
                        &mut reader,
                        client,
                        filter.policy,
                        filter.server,
                        filter.method,
                    )?
                };
                if removed > 0 {
                    eprintln!(
                        "agentfence mcp http-proxy: filtered {removed} streamed item(s) from {}",
                        filter.method
                    );
                }
                client
                    .flush()
                    .context("failed to flush filtered streamed HTTP response")?;
                return Ok(ForwardedHttpResponse::Streamed);
            }
        }
        write_http_response_head(client, status, &reason, &headers)?;
        io::copy(&mut reader, client).context("failed to stream upstream response")?;
        client
            .flush()
            .context("failed to flush streamed HTTP response")?;
        return Ok(ForwardedHttpResponse::Streamed);
    }

    let body = if let Some(length) =
        header_value(&headers, "content-length").and_then(|value| value.parse::<usize>().ok())
    {
        let mut body = vec![0_u8; length];
        reader
            .read_exact(&mut body)
            .context("failed to read upstream response body")?;
        body
    } else {
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .context("failed to read upstream response body")?;
        body
    };
    let content_type = header_value(&headers, "content-type")
        .unwrap_or("application/json")
        .to_string();

    Ok(ForwardedHttpResponse::Complete(SimpleHttpResponse {
        status,
        content_type,
        body,
    }))
}

fn write_upstream_http_request(
    stream: &mut TcpStream,
    upstream: &HttpUpstream,
    request: &SimpleHttpRequest,
) -> Result<()> {
    let upstream_path = upstream_path_for_request(upstream, request);
    let request_head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        request.method, upstream_path, upstream.authority
    );
    stream
        .write_all(request_head.as_bytes())
        .context("failed to write upstream request headers")?;
    let mut has_content_type = false;
    let mut has_accept = false;
    for (name, value) in &request.headers {
        if !http_header_is_forwardable(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        if name.eq_ignore_ascii_case("accept") {
            has_accept = true;
        }
        write!(stream, "{name}: {value}\r\n").context("failed to write upstream header")?;
    }
    if request.method == "POST" && !has_content_type {
        stream
            .write_all(b"Content-Type: application/json\r\n")
            .context("failed to write upstream content type")?;
    }
    if request.method == "POST" && !has_accept {
        stream
            .write_all(b"Accept: application/json, text/event-stream\r\n")
            .context("failed to write upstream accept header")?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        request.body.len()
    )
    .context("failed to write upstream request terminator")?;
    if !request.body.is_empty() {
        stream
            .write_all(&request.body)
            .context("failed to write upstream request body")?;
    }
    stream.flush().context("failed to flush upstream request")?;
    Ok(())
}

fn read_http_response_head<R>(reader: &mut R) -> Result<(u16, String, Vec<(String, String)>)>
where
    R: BufRead,
{
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .context("failed to read upstream HTTP status line")?;
    if status_line.trim().is_empty() {
        bail!("empty upstream HTTP response");
    }
    let (status, reason) = parse_http_status_line(status_line.trim_end_matches(['\r', '\n']))?;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("failed to read upstream HTTP header")?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok((status, reason, headers))
}

fn parse_http_status_line(status_line: &str) -> Result<(u16, String)> {
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().context("invalid upstream HTTP status line")?;
    let status = parts
        .next()
        .context("invalid upstream HTTP status line")?
        .parse::<u16>()
        .context("invalid upstream HTTP status code")?;
    let reason = parts.collect::<Vec<_>>().join(" ");
    Ok((
        status,
        if reason.is_empty() {
            default_http_reason(status).to_string()
        } else {
            reason
        },
    ))
}

fn response_should_stream(method: &str, headers: &[(String, String)]) -> bool {
    header_value(headers, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("text/event-stream")
    }) || header_value(headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
        || (method == "GET" && header_value(headers, "content-length").is_none())
}

fn response_is_event_stream(headers: &[(String, String)]) -> bool {
    header_value(headers, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("text/event-stream")
    })
}

fn response_is_chunked(headers: &[(String, String)]) -> bool {
    header_value(headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
}

fn filter_sse_list_stream<R, W>(
    reader: &mut R,
    writer: &mut W,
    policy: &Policy,
    server: &str,
    method: &str,
) -> Result<usize>
where
    R: BufRead,
    W: Write,
{
    let mut removed_total = 0_usize;
    let mut event_lines = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .context("failed to read SSE event line")?;
        if read == 0 {
            if !event_lines.is_empty() {
                removed_total +=
                    write_filtered_sse_event(writer, &event_lines, policy, server, method)?;
            }
            break;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            removed_total +=
                write_filtered_sse_event(writer, &event_lines, policy, server, method)?;
            event_lines.clear();
        } else {
            event_lines.push(trimmed);
        }
    }

    Ok(removed_total)
}

fn write_filtered_sse_event<W>(
    writer: &mut W,
    lines: &[String],
    policy: &Policy,
    server: &str,
    method: &str,
) -> Result<usize>
where
    W: Write,
{
    if lines.is_empty() {
        writer
            .write_all(b"\n")
            .context("failed to write empty SSE event")?;
        return Ok(0);
    }

    let data = lines
        .iter()
        .filter_map(|line| sse_data_value(line))
        .collect::<Vec<_>>()
        .join("\n");
    if !data.is_empty() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&data) {
            let filtered = agentfence_mcp::filter_list_response(policy, server, method, &value);
            if filtered.removed > 0 {
                for line in lines.iter().filter(|line| sse_data_value(line).is_none()) {
                    writer
                        .write_all(line.as_bytes())
                        .context("failed to write SSE event field")?;
                    writer
                        .write_all(b"\n")
                        .context("failed to write SSE event newline")?;
                }
                writer
                    .write_all(b"data: ")
                    .context("failed to write SSE data prefix")?;
                serde_json::to_writer(&mut *writer, &filtered.response)
                    .context("failed to encode filtered SSE data")?;
                writer
                    .write_all(b"\n\n")
                    .context("failed to finish filtered SSE event")?;
                return Ok(filtered.removed);
            }
        }
    }

    for line in lines {
        writer
            .write_all(line.as_bytes())
            .context("failed to write SSE event line")?;
        writer
            .write_all(b"\n")
            .context("failed to write SSE event newline")?;
    }
    writer
        .write_all(b"\n")
        .context("failed to finish SSE event")?;
    Ok(0)
}

fn sse_data_value(line: &str) -> Option<&str> {
    let value = line.strip_prefix("data:")?;
    Some(value.strip_prefix(' ').unwrap_or(value))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn http_header_is_forwardable(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "connection" | "content-length" | "transfer-encoding" | "proxy-connection"
    )
}

fn upstream_path_for_request(upstream: &HttpUpstream, request: &SimpleHttpRequest) -> String {
    let Some((_, query)) = request.path.split_once('?') else {
        return upstream.path.clone();
    };
    if upstream.path.contains('?') {
        format!("{}&{query}", upstream.path)
    } else {
        format!("{}?{query}", upstream.path)
    }
}

#[cfg(test)]
fn parse_http_response(response: &[u8]) -> Result<SimpleHttpResponse> {
    let Some(split) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        bail!("invalid upstream HTTP response");
    };
    let head = String::from_utf8_lossy(&response[..split]);
    let body = response[split + 4..].to_vec();
    let mut lines = head.lines();
    let status_line = lines.next().context("missing upstream HTTP status line")?;
    let (status, _reason) = parse_http_status_line(status_line)?;
    let mut content_type = "application/json".to_string();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_string();
            }
        }
    }

    Ok(SimpleHttpResponse {
        status,
        content_type,
        body,
    })
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = default_http_reason(status);
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .context("failed to write HTTP response headers")?;
    stream
        .write_all(body)
        .context("failed to write HTTP response body")?;
    stream.flush().context("failed to flush HTTP response")?;
    Ok(())
}

fn write_http_response_head(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
) -> Result<()> {
    write!(stream, "HTTP/1.1 {status} {reason}\r\n")
        .context("failed to write HTTP response status")?;
    let mut has_connection = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        write!(stream, "{name}: {value}\r\n").context("failed to write HTTP response header")?;
    }
    if !has_connection {
        stream
            .write_all(b"Connection: close\r\n")
            .context("failed to write HTTP connection header")?;
    }
    stream
        .write_all(b"\r\n")
        .context("failed to finish HTTP response headers")?;
    stream
        .flush()
        .context("failed to flush HTTP response head")?;
    Ok(())
}

fn write_http_filtered_stream_head<W>(
    stream: &mut W,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
) -> Result<()>
where
    W: Write,
{
    write!(stream, "HTTP/1.1 {status} {reason}\r\n")
        .context("failed to write HTTP response status")?;
    let mut has_content_type = false;
    for (name, value) in headers {
        if !http_filtered_stream_header_is_forwardable(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        write!(stream, "{name}: {value}\r\n").context("failed to write HTTP response header")?;
    }
    if !has_content_type {
        stream
            .write_all(b"Content-Type: text/event-stream\r\n")
            .context("failed to write HTTP content type")?;
    }
    stream
        .write_all(b"Connection: close\r\n\r\n")
        .context("failed to finish filtered HTTP response headers")?;
    stream
        .flush()
        .context("failed to flush filtered HTTP response head")?;
    Ok(())
}

fn http_filtered_stream_header_is_forwardable(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "content-length" | "transfer-encoding" | "proxy-connection"
    )
}

struct ChunkedBodyReader<R> {
    reader: R,
    remaining: usize,
    done: bool,
}

impl<R> ChunkedBodyReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            remaining: 0,
            done: false,
        }
    }
}

impl<R> Read for ChunkedBodyReader<R>
where
    R: BufRead,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.done {
            return Ok(0);
        }

        if self.remaining == 0 {
            self.remaining = self.read_next_chunk_size()?;
            if self.done {
                return Ok(0);
            }
        }

        let to_read = self.remaining.min(output.len());
        let read = self.reader.read(&mut output[..to_read])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF in HTTP chunk",
            ));
        }
        self.remaining -= read;
        if self.remaining == 0 {
            self.consume_chunk_crlf()?;
        }
        Ok(read)
    }
}

impl<R> ChunkedBodyReader<R>
where
    R: BufRead,
{
    fn read_next_chunk_size(&mut self) -> io::Result<usize> {
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        if line.is_empty() {
            self.done = true;
            return Ok(0);
        }
        let raw_size = line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(raw_size, 16).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HTTP chunk size {raw_size}: {error}"),
            )
        })?;
        if size == 0 {
            self.done = true;
            self.consume_trailers()?;
        }
        Ok(size)
    }

    fn consume_chunk_crlf(&mut self) -> io::Result<()> {
        let mut crlf = [0_u8; 2];
        self.reader.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTP chunk terminator",
            ));
        }
        Ok(())
    }

    fn consume_trailers(&mut self) -> io::Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            self.reader.read_line(&mut line)?;
            if line.is_empty() || line.trim_end_matches(['\r', '\n']).is_empty() {
                return Ok(());
            }
        }
    }
}

fn default_http_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn mcp_proxy(args: McpProxyArgs) -> Result<ExitCode> {
    let cwd = env::current_dir().context("failed to read current directory")?;
    let policy_path = resolve_policy_path(args.policy.as_deref(), &cwd)?;
    let policy = load_policy(&policy_path)?;
    let policy_for_upstream = policy.clone();
    let server_for_upstream = args.server.clone();
    let mut rate_limiter = agentfence_mcp::McpRateLimiter::for_server(&policy, &args.server);
    let audit_store = if policy.audit.enabled {
        Some(AuditStore::open(
            args.audit
                .clone()
                .unwrap_or_else(|| PathBuf::from(&policy.audit.store)),
        )?)
    } else {
        None
    };

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
        append_mcp_audit(
            audit_store.as_ref(),
            &decision.request,
            if allowed {
                &decision.decision
            } else {
                &denial_decision
            },
            allowed,
        )?;

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

fn append_mcp_audit(
    store: Option<&AuditStore>,
    request: &agentfence_mcp::McpAccessRequest,
    decision: &DecisionResult,
    allowed: bool,
) -> Result<()> {
    let Some(store) = store else {
        return Ok(());
    };

    let mut event = AuditEvent::new(
        "mcp-proxy",
        format!("mcp.{}", request.kind),
        format!("{}/{}", request.server, request.name),
        if allowed { "allow" } else { "deny" },
        format!("{:?}", decision.risk).to_ascii_lowercase(),
        decision.reason.clone(),
    );
    event.matched_rule = decision.matched_rule.clone();
    event.metadata = serde_json::json!({
        "server": &request.server,
        "kind": &request.kind,
        "name": &request.name,
        "arguments": &request.arguments,
        "decision": decision.decision
    });
    store.append(&event)
}

fn append_mcp_audit_for_path(
    path: Option<&Path>,
    request: &agentfence_mcp::McpAccessRequest,
    decision: &DecisionResult,
    allowed: bool,
) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let store = AuditStore::open(path)?;
    append_mcp_audit(Some(&store), request, decision, allowed)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_upstream_with_path_and_default_port() {
        let upstream = parse_http_upstream("http://127.0.0.1:3000/mcp").expect("upstream");
        assert_eq!(upstream.authority, "127.0.0.1:3000");
        assert_eq!(upstream.connect_addr, "127.0.0.1:3000");
        assert_eq!(upstream.path, "/mcp");

        let upstream = parse_http_upstream("http://localhost").expect("upstream");
        assert_eq!(upstream.authority, "localhost");
        assert_eq!(upstream.connect_addr, "localhost:80");
        assert_eq!(upstream.path, "/");
    }

    #[test]
    fn rejects_non_http_upstream_urls() {
        assert!(parse_http_upstream("https://example.com/mcp").is_err());
    }

    #[test]
    fn parses_simple_http_response() {
        let response =
            b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let parsed = parse_http_response(response).expect("response");

        assert_eq!(parsed.status, 201);
        assert_eq!(parsed.content_type, "application/json");
        assert_eq!(parsed.body, br#"{"ok":true}"#);
    }

    #[test]
    fn parses_http_status_reason() {
        let (status, reason) = parse_http_status_line("HTTP/1.1 201 Created").expect("status");

        assert_eq!(status, 201);
        assert_eq!(reason, "Created");
    }

    #[test]
    fn detects_streaming_http_responses() {
        let event_stream = vec![("Content-Type".to_string(), "text/event-stream".to_string())];
        assert!(response_should_stream("GET", &event_stream));

        let chunked = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        assert!(response_should_stream("POST", &chunked));

        let sized_get = vec![("Content-Length".to_string(), "2".to_string())];
        assert!(!response_should_stream("GET", &sized_get));
    }

    #[test]
    fn filters_sse_list_response_events() {
        let policy = policy_denying_merge_pull_request();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    { "name": "list_pull_requests" },
                    { "name": "merge_pull_request" }
                ]
            }
        });
        let event_stream = format!(
            "event: message\ndata: {}\n\n: keepalive\n\ndata: [DONE]\n\n",
            payload
        );
        let mut reader = BufReader::new(std::io::Cursor::new(event_stream.into_bytes()));
        let mut output = Vec::new();

        let removed =
            filter_sse_list_stream(&mut reader, &mut output, &policy, "github", "tools/list")
                .expect("filter");
        let output = String::from_utf8(output).expect("utf8");

        assert_eq!(removed, 1);
        assert!(output.contains("event: message"));
        assert!(output.contains("list_pull_requests"));
        assert!(!output.contains("merge_pull_request"));
        assert!(output.contains(": keepalive"));
        assert!(output.contains("data: [DONE]"));
    }

    #[test]
    fn filters_chunked_sse_list_response_events() {
        let policy = policy_denying_merge_pull_request();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    { "name": "list_pull_requests" },
                    { "name": "merge_pull_request" }
                ]
            }
        });
        let body = format!("data: {}\n\n", payload);
        let chunked = format!("{:x}\r\n{}\r\n0\r\n\r\n", body.len(), body);
        let chunked_reader =
            ChunkedBodyReader::new(BufReader::new(std::io::Cursor::new(chunked.into_bytes())));
        let mut reader = BufReader::new(chunked_reader);
        let mut output = Vec::new();

        let removed =
            filter_sse_list_stream(&mut reader, &mut output, &policy, "github", "tools/list")
                .expect("filter");
        let output = String::from_utf8(output).expect("utf8");

        assert_eq!(removed, 1);
        assert!(output.contains("list_pull_requests"));
        assert!(!output.contains("merge_pull_request"));
    }

    #[test]
    fn filtered_stream_head_removes_length_and_transfer_encoding() {
        let headers = vec![
            ("Content-Type".to_string(), "text/event-stream".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Content-Length".to_string(), "120".to_string()),
            ("Cache-Control".to_string(), "no-cache".to_string()),
        ];
        let mut output = Vec::new();

        write_http_filtered_stream_head(&mut output, 200, "OK", &headers).expect("head");
        let output = String::from_utf8(output).expect("utf8");

        assert!(output.contains("Content-Type: text/event-stream"));
        assert!(output.contains("Cache-Control: no-cache"));
        assert!(output.contains("Connection: close"));
        assert!(!output.contains("Transfer-Encoding"));
        assert!(!output.contains("Content-Length"));
    }

    fn policy_denying_merge_pull_request() -> Policy {
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
        policy
    }

    #[test]
    fn appends_client_query_to_upstream_path() {
        let upstream = parse_http_upstream("http://127.0.0.1:3000/mcp").expect("upstream");
        let request = SimpleHttpRequest {
            method: "GET".to_string(),
            path: "/mcp?session=abc".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };

        assert_eq!(
            upstream_path_for_request(&upstream, &request),
            "/mcp?session=abc"
        );

        let upstream =
            parse_http_upstream("http://127.0.0.1:3000/mcp?transport=sse").expect("upstream");
        assert_eq!(
            upstream_path_for_request(&upstream, &request),
            "/mcp?transport=sse&session=abc"
        );
    }

    #[test]
    fn quotes_shell_and_powershell_arguments() {
        assert_eq!(
            quote_command(
                &["agentfence", "run", "--", "npm install"],
                IntegrationFormat::Shell
            ),
            "agentfence run -- 'npm install'"
        );
        assert_eq!(
            quote_arg("can't", IntegrationFormat::PowerShell),
            "'can''t'"
        );
    }

    #[test]
    fn renders_integration_wrapper_scripts() {
        let codex = integration_profile_spec(IntegrationProfile::Codex);
        let shell = integration_script(codex, IntegrationFormat::Shell).expect("shell script");
        assert!(shell.starts_with("#!/usr/bin/env sh"));
        assert!(shell.contains("exec agentfence run --actor codex -- codex \"$@\""));

        let powershell =
            integration_script(codex, IntegrationFormat::PowerShell).expect("powershell script");
        assert!(powershell.contains("[string[]]$AgentFenceArgs"));
        assert!(powershell.contains("& agentfence run --actor codex -- codex @AgentFenceArgs"));
    }

    #[test]
    fn names_integration_wrapper_files_by_format() {
        let codex = integration_profile_spec(IntegrationProfile::Codex);

        assert_eq!(
            integration_wrapper_filename(codex, IntegrationFormat::Shell),
            "agentfence-codex"
        );
        assert_eq!(
            integration_wrapper_filename(codex, IntegrationFormat::PowerShell),
            "agentfence-codex.ps1"
        );
    }

    #[test]
    fn detects_wrapper_directory_in_path_env() {
        let wrapper_dir = PathBuf::from(if cfg!(windows) {
            r"C:\agentfence\wrappers"
        } else {
            "/opt/agentfence/wrappers"
        });
        let other_dir = PathBuf::from(if cfg!(windows) {
            r"C:\tools"
        } else {
            "/usr/local/bin"
        });
        let path_env =
            env::join_paths([other_dir.as_os_str(), wrapper_dir.as_os_str()]).expect("PATH");

        assert!(path_env_contains_dir(
            &wrapper_dir,
            Some(path_env.as_os_str())
        ));
        assert!(!path_env_contains_dir(
            Path::new(if cfg!(windows) {
                r"C:\agentfence\other"
            } else {
                "/opt/agentfence/other"
            }),
            Some(path_env.as_os_str())
        ));
    }

    #[test]
    fn normalizes_path_env_entries() {
        assert!(paths_match_for_env(
            Path::new(if cfg!(windows) {
                r"C:\AgentFence\Wrappers\"
            } else {
                "/opt/agentfence/wrappers/"
            }),
            Path::new(if cfg!(windows) {
                r"c:\agentfence\wrappers"
            } else {
                "/opt/agentfence/wrappers"
            })
        ));
    }

    #[test]
    fn audit_report_summarizes_and_escapes_review_events() {
        let events = vec![
            AuditEvent::new("codex", "shell.exec", "git status", "allow", "low", "ok"),
            AuditEvent::new(
                "claude|code",
                "mcp.tool",
                "github/merge\npull_request",
                "deny",
                "medium",
                "blocked",
            ),
        ];
        let report = audit_report_json(&events, 20);

        assert_eq!(report["totalEvents"], 2);
        assert_eq!(report["decisions"]["allow"], 1);
        assert_eq!(report["decisions"]["deny"], 1);
        assert_eq!(
            report["reviewEvents"]
                .as_array()
                .expect("review events")
                .len(),
            1
        );
        assert_eq!(escape_markdown_table("a|b\nc"), "a\\|b c");
    }

    #[test]
    fn parses_shell_lines_with_quotes_and_escapes() {
        assert_eq!(
            parse_shell_line("git commit -m \"hello world\"").expect("parse"),
            vec!["git", "commit", "-m", "hello world"]
        );
        assert_eq!(
            parse_shell_line("echo one\\ two 'three four'").expect("parse"),
            vec!["echo", "one two", "three four"]
        );
        assert!(parse_shell_line("echo \"unterminated").is_err());
    }

    #[test]
    fn detects_cd_command_case_insensitively() {
        assert!(is_cd_command(&["CD".to_string(), "..".to_string()]));
        assert!(!is_cd_command(&["pwd".to_string()]));
    }

    #[test]
    fn policy_templates_set_expected_guardrails() {
        let engineering =
            build_policy_template(PolicyTemplate::EngineeringDefault, Some("app".to_string()));
        assert_eq!(engineering.project.as_deref(), Some("app"));
        assert!(engineering.actors.contains_key("codex"));
        assert_eq!(
            engineering.mcp.servers["github"].tools["merge_pull_request"],
            Decision::Deny
        );

        let read_only = build_policy_template(PolicyTemplate::ReadOnlyAudit, None);
        assert_eq!(read_only.default_decision, Decision::Deny);
        assert_eq!(read_only.filesystem.write.decision, Decision::Deny);
        assert!(!read_only.approval.remember_choices);

        let release = build_policy_template(PolicyTemplate::ReleaseGuard, None);
        assert_eq!(release.network.default_decision, Decision::Deny);
        assert!(release.skills.deny.contains(&"release-publish".to_string()));
        assert!(
            release
                .shell
                .rules
                .iter()
                .any(|rule| rule.id == "deny-release-publish")
        );
    }
}
