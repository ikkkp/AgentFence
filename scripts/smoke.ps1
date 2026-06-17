param(
  [switch]$SkipCargoBuild
)

$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host ""
  Write-Host "==> $Message"
}

function Invoke-Checked {
  param(
    [string]$Description,
    [scriptblock]$Command
  )

  Write-Step $Description
  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $output = & $Command 2>&1 | ForEach-Object { $_.ToString() }
    $exitCode = $LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  $text = ($output | Out-String).TrimEnd()
  if ($text.Length -gt 0) {
    Write-Host $text
  }
  if ($exitCode -ne 0) {
    throw "$Description failed with exit code $exitCode"
  }
  return $text
}

function Assert-Contains {
  param(
    [string]$Text,
    [string]$Expected,
    [string]$Context
  )

  if (-not $Text.Contains($Expected)) {
    throw "$Context did not contain expected text: $Expected"
  }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$repoRoot = $repoRoot.Path

if (-not $SkipCargoBuild) {
  Invoke-Checked "Build AgentFence binaries" {
    cargo build --manifest-path (Join-Path $repoRoot "Cargo.toml") --bin agentfence --bin agentfenced
  } | Out-Null
}

$binaryName = "agentfence"
if ($env:OS -eq "Windows_NT") {
  $binaryName = "agentfence.exe"
}
$agentfence = Join-Path $repoRoot (Join-Path "target" (Join-Path "debug" $binaryName))
if (-not (Test-Path -LiteralPath $agentfence)) {
  throw "agentfence binary was not found at $agentfence"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("agentfence-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

try {
  Push-Location $tempRoot

  Invoke-Checked "Initialize a project policy" {
    & $agentfence init --force --project smoke --preset developer
  } | Out-Null

  $validate = Invoke-Checked "Validate generated policy" {
    & $agentfence policy validate agentfence.policy.json
  }
  Assert-Contains $validate "valid policy" "policy validate"

  $check = Invoke-Checked "Check a read-only shell command" {
    & $agentfence check --actor codex -- git status
  }
  Assert-Contains $check "decision: Allow" "shell check"

  $simulate = Invoke-Checked "Simulate a development command" {
    & $agentfence simulate shell --actor codex -- npm test
  }
  Assert-Contains $simulate '"summary": "ordinary development command"' "shell simulation"

  $filesystem = Invoke-Checked "Check filesystem access" {
    & $agentfence filesystem check --operation read --path agentfence.policy.json
  }
  Assert-Contains $filesystem "decision: Allow" "filesystem check"

  $network = Invoke-Checked "Check allowed network domain" {
    & $agentfence network check --domain github.com
  }
  Assert-Contains $network "decision: Allow" "network check"

  $skill = Invoke-Checked "Check allowed skill access" {
    & $agentfence skill check --name code-review
  }
  Assert-Contains $skill "decision: Allow" "skill check"

  $list = Invoke-Checked "List integration profiles" {
    & $agentfence integrations list
  }
  Assert-Contains $list "codex" "integration list"
  Assert-Contains $list "claude-code" "integration list"

  Invoke-Checked "Generate a Codex PowerShell wrapper" {
    & $agentfence integrations install codex --format powershell --output-dir wrappers --force
  } | Out-Null
  $codexWrapper = Join-Path (Join-Path $tempRoot "wrappers") "agentfence-codex.ps1"
  if (-not (Test-Path -LiteralPath $codexWrapper)) {
    throw "Codex wrapper was not created"
  }

  Pop-Location

  $policyPath = Join-Path $repoRoot "agentfence.policy.json"
  $mcpAllow = Invoke-Checked "Check allowed MCP tool policy" {
    & $agentfence mcp check --server github --kind tool --name list_issues --policy $policyPath
  }
  Assert-Contains $mcpAllow '"decision": "allow"' "MCP allow check"

  $mcpDeny = Invoke-Checked "Check denied MCP tool policy" {
    & $agentfence mcp check --server github --kind tool --name merge_pull_request --policy $policyPath
  }
  Assert-Contains $mcpDeny '"decision": "deny"' "MCP deny check"

  $dangerousMcpArgumentsPath = Join-Path $tempRoot "mcp-arguments.json"
  Set-Content -LiteralPath $dangerousMcpArgumentsPath -Encoding UTF8 -Value '{"api_key":"sk-test"}'
  $mcpArgumentInspection = Invoke-Checked "Check MCP argument inspection" {
    & $agentfence mcp check --server github --kind tool --name list_issues --arguments-file $dangerousMcpArgumentsPath --policy $policyPath
  }
  Assert-Contains $mcpArgumentInspection '"decision": "ask"' "MCP argument inspection"
  Assert-Contains $mcpArgumentInspection '"matchedRule": "mcp.argumentInspection"' "MCP argument inspection"

  $auditPath = Join-Path $tempRoot "smoke-audit.sqlite"
  Push-Location $repoRoot
  Invoke-Checked "Run an allowed guarded command and write audit log" {
    & $agentfence run --actor codex --audit $auditPath -- git status --short
  } | Out-Null
  Pop-Location

  $auditJson = Join-Path $tempRoot "audit.json"
  $auditExport = Invoke-Checked "Export audit events" {
    & $agentfence audit export --audit $auditPath --format json --limit 10 --output $auditJson
  }
  Assert-Contains $auditExport "exported audit log" "audit export"

  $auditContent = Get-Content -Raw -LiteralPath $auditJson
  Assert-Contains $auditContent '"action": "shell.exec"' "audit file"
  Assert-Contains $auditContent '"decision": "allow"' "audit file"
}
finally {
  while ((Get-Location).Path -ne $repoRoot -and (Get-Location).Path.StartsWith($tempRoot)) {
    Pop-Location
  }
  Remove-Item -Recurse -Force -LiteralPath $tempRoot -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "AgentFence smoke checks passed."
