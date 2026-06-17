use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryReport {
    pub os: String,
    pub arch: String,
    pub cwd: String,
    pub checks: Vec<BoundaryCheck>,
    pub proxy_env: Vec<String>,
    pub tools: Vec<ToolAvailability>,
    pub sensitive_paths: Vec<SensitivePath>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryCheck {
    pub id: String,
    pub title: String,
    pub status: BoundaryStatus,
    pub severity: BoundarySeverity,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundaryStatus {
    Configured,
    Available,
    Advisory,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundarySeverity {
    Info,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAvailability {
    pub name: String,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SensitivePath {
    pub label: String,
    pub path: String,
    pub exists: bool,
}

pub fn inspect_boundary(cwd: &Path) -> BoundaryReport {
    let proxy_env = configured_proxy_env();
    let tool_names = boundary_tool_names();
    let tools = tool_names
        .iter()
        .map(|name| ToolAvailability {
            name: (*name).to_string(),
            available: command_exists(name),
        })
        .collect::<Vec<_>>();
    let sensitive_paths = sensitive_path_candidates(cwd);
    let detected_sensitive_paths = sensitive_paths.iter().filter(|path| path.exists).count();
    let wrappers_path = cwd.join(".agentfence").join("wrappers");
    let wrappers_on_path = path_env_contains(&wrappers_path);
    let policy_exists = cwd.join("agentfence.policy.json").exists();
    let os_boundary_tools = tools
        .iter()
        .filter(|tool| tool.available && os_boundary_tool(tool.name.as_str()))
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();

    let mut checks = Vec::new();
    checks.push(BoundaryCheck {
        id: "project-policy".to_string(),
        title: "Project policy file".to_string(),
        status: if policy_exists {
            BoundaryStatus::Configured
        } else {
            BoundaryStatus::Missing
        },
        severity: if policy_exists {
            BoundarySeverity::Info
        } else {
            BoundarySeverity::Medium
        },
        detail: if policy_exists {
            "agentfence.policy.json is present in the project root".to_string()
        } else {
            "agentfence.policy.json was not found in the inspected directory".to_string()
        },
        recommendation: "Run agentfence init or point commands at an explicit policy path."
            .to_string(),
    });
    checks.push(BoundaryCheck {
        id: "agent-wrappers-path".to_string(),
        title: "Agent wrapper directory on PATH".to_string(),
        status: if wrappers_on_path {
            BoundaryStatus::Configured
        } else {
            BoundaryStatus::Advisory
        },
        severity: BoundarySeverity::Info,
        detail: if wrappers_on_path {
            format!("{} is on PATH", wrappers_path.display())
        } else {
            format!("{} is not currently on PATH", wrappers_path.display())
        },
        recommendation:
            "Use agentfence integrations install --add-to-path for wrapper-based agent launches."
                .to_string(),
    });
    checks.push(BoundaryCheck {
        id: "proxy-env".to_string(),
        title: "Process proxy environment".to_string(),
        status: if proxy_env.is_empty() {
            BoundaryStatus::Missing
        } else {
            BoundaryStatus::Configured
        },
        severity: BoundarySeverity::Info,
        detail: if proxy_env.is_empty() {
            "No HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, or NO_PROXY variables are set".to_string()
        } else {
            format!("configured variables: {}", proxy_env.join(", "))
        },
        recommendation:
            "Proxy variables are advisory for cooperative tools; enforce MCP traffic with AgentFence proxies."
                .to_string(),
    });
    checks.push(BoundaryCheck {
        id: "os-boundary-tools".to_string(),
        title: "OS boundary helper tools".to_string(),
        status: if os_boundary_tools.is_empty() {
            BoundaryStatus::Advisory
        } else {
            BoundaryStatus::Available
        },
        severity: BoundarySeverity::Medium,
        detail: if os_boundary_tools.is_empty() {
            "No OS boundary helper tools were found on PATH for this platform".to_string()
        } else {
            format!("available tools: {}", os_boundary_tools.join(", "))
        },
        recommendation:
            "Treat this as discovery only; future AgentFence releases can bind these helpers into enforced profiles."
                .to_string(),
    });
    checks.push(BoundaryCheck {
        id: "sensitive-local-paths".to_string(),
        title: "Sensitive local paths".to_string(),
        status: if detected_sensitive_paths == 0 {
            BoundaryStatus::Missing
        } else {
            BoundaryStatus::Advisory
        },
        severity: if detected_sensitive_paths == 0 {
            BoundarySeverity::Info
        } else {
            BoundarySeverity::High
        },
        detail: format!("{detected_sensitive_paths} sensitive path candidates detected"),
        recommendation:
            "Keep sensitive paths denied or ask-gated in policy before enabling broader agent wrappers."
                .to_string(),
    });

    let recommendations = checks
        .iter()
        .filter(|check| !matches!(check.status, BoundaryStatus::Configured))
        .map(|check| check.recommendation.clone())
        .collect::<Vec<_>>();

    BoundaryReport {
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        cwd: cwd.display().to_string(),
        checks,
        proxy_env,
        tools,
        sensitive_paths,
        recommendations,
    }
}

fn configured_proxy_env() -> Vec<String> {
    [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ]
    .into_iter()
    .filter(|name| env::var_os(name).is_some_and(|value| !value.is_empty()))
    .map(str::to_string)
    .collect()
}

fn sensitive_path_candidates(cwd: &Path) -> Vec<SensitivePath> {
    let home = home_dir();
    let mut paths = vec![
        ("Project .env", cwd.join(".env")),
        ("Project .env.local", cwd.join(".env.local")),
    ];
    if let Some(home) = home.as_ref() {
        paths.extend([
            ("SSH keys", home.join(".ssh")),
            ("AWS credentials", home.join(".aws")),
            ("Kubernetes config", home.join(".kube")),
            ("Docker config", home.join(".docker")),
            ("Azure config", home.join(".azure")),
            ("Google Cloud config", home.join(".config").join("gcloud")),
            ("npm token config", home.join(".npmrc")),
            ("Python package token config", home.join(".pypirc")),
        ]);
    }

    paths
        .into_iter()
        .map(|(label, path)| SensitivePath {
            label: label.to_string(),
            exists: path.exists(),
            path: display_path(&path, home.as_deref()),
        })
        .collect()
}

fn display_path(path: &Path, home: Option<&Path>) -> String {
    if let Some(home) = home {
        if let Ok(relative) = path.strip_prefix(home) {
            if relative.as_os_str().is_empty() {
                return "~".to_string();
            }
            return format!("~{}{}", std::path::MAIN_SEPARATOR, relative.display());
        }
    }
    path.display().to_string()
}

fn boundary_tool_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &[
            "agentfence",
            "codex",
            "claude",
            "git",
            "ssh",
            "curl",
            "npm",
            "pnpm",
            "docker",
            "kubectl",
            "terraform",
            "gh",
            "netsh",
            "powershell",
            "pwsh",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "agentfence",
            "codex",
            "claude",
            "git",
            "ssh",
            "curl",
            "npm",
            "pnpm",
            "docker",
            "kubectl",
            "terraform",
            "gh",
            "pfctl",
            "networksetup",
            "sandbox-exec",
        ]
    } else {
        &[
            "agentfence",
            "codex",
            "claude",
            "git",
            "ssh",
            "curl",
            "wget",
            "npm",
            "pnpm",
            "docker",
            "kubectl",
            "terraform",
            "gh",
            "bwrap",
            "firejail",
            "unshare",
            "iptables",
            "nft",
        ]
    }
}

fn os_boundary_tool(name: &str) -> bool {
    matches!(
        name,
        "netsh"
            | "powershell"
            | "pwsh"
            | "pfctl"
            | "networksetup"
            | "sandbox-exec"
            | "bwrap"
            | "firejail"
            | "unshare"
            | "iptables"
            | "nft"
    )
}

fn command_exists(name: &str) -> bool {
    let Some(path_env) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_env).any(|directory| {
        executable_candidates(name)
            .into_iter()
            .any(|candidate| directory.join(candidate).is_file())
    })
}

fn executable_candidates(name: &str) -> Vec<String> {
    if cfg!(windows) && Path::new(name).extension().is_none() {
        let extensions = env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension| !extension.is_empty())
                    .map(|extension| extension.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![
                    ".exe".to_string(),
                    ".cmd".to_string(),
                    ".bat".to_string(),
                    ".com".to_string(),
                ]
            });
        extensions
            .into_iter()
            .flat_map(|extension| {
                [
                    format!("{name}{extension}"),
                    format!("{name}{}", extension.to_ascii_uppercase()),
                ]
            })
            .collect()
    } else {
        vec![name.to_string()]
    }
}

fn path_env_contains(path: &Path) -> bool {
    let Ok(target) = path.canonicalize() else {
        return false;
    };
    env::var_os("PATH").is_some_and(|path_env| {
        env::split_paths(&path_env).any(|entry| {
            entry
                .canonicalize()
                .is_ok_and(|candidate| paths_equal(&candidate, &target))
        })
    })
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_candidates_include_windows_extensions() {
        let candidates = executable_candidates("agentfence");
        if cfg!(windows) {
            assert!(
                candidates
                    .iter()
                    .any(|candidate| candidate.ends_with(".exe"))
            );
        } else {
            assert_eq!(candidates, vec!["agentfence".to_string()]);
        }
    }

    #[test]
    fn boundary_report_redacts_proxy_values() {
        let cwd = env::current_dir().expect("cwd");
        let report = inspect_boundary(&cwd);
        let serialized = serde_json::to_string(&report).expect("json");

        assert!(!serialized.contains("://"));
    }

    #[test]
    fn display_path_replaces_home_prefix() {
        let home = Path::new(if cfg!(windows) {
            r"C:\Users\AgentFence"
        } else {
            "/home/agentfence"
        });
        let path = home.join(".ssh");

        assert!(display_path(&path, Some(home)).starts_with('~'));
    }
}
