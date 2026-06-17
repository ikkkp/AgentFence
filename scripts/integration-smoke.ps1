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

function Read-CanonicalJson {
  param([string]$Json)
  return (($Json | ConvertFrom-Json) | ConvertTo-Json -Depth 20 -Compress)
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$repoRoot = $repoRoot.Path

if (-not $SkipCargoBuild) {
  Invoke-Checked "Build AgentFence CLI" {
    cargo build --manifest-path (Join-Path $repoRoot "Cargo.toml") --bin agentfence
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

$profiles = @(
  @{
    Name = "codex"
    Example = "examples/integrations/codex-wrapper.json"
    ShellSnippet = 'exec agentfence run --actor codex -- codex "$@"'
    PowerShellSnippet = '& agentfence run --actor codex -- codex @AgentFenceArgs'
    WrapperBase = "agentfence-codex"
  },
  @{
    Name = "claude-code"
    Example = "examples/integrations/claude-code-wrapper.json"
    ShellSnippet = 'exec agentfence run --actor claude-code -- claude "$@"'
    PowerShellSnippet = '& agentfence run --actor claude-code -- claude @AgentFenceArgs'
    WrapperBase = "agentfence-claude-code"
  },
  @{
    Name = "cursor-style"
    Example = "examples/integrations/cursor-style-wrapper.json"
    ShellSnippet = 'exec agentfence run --actor cursor-agent -- node ./agent-entrypoint.js "$@"'
    PowerShellSnippet = '& agentfence run --actor cursor-agent -- node ./agent-entrypoint.js @AgentFenceArgs'
    WrapperBase = "agentfence-cursor-style"
  },
  @{
    Name = "generic-mcp"
    Example = "examples/integrations/generic-mcp-proxy.json"
    ShellSnippet = 'exec agentfence mcp proxy --server github --ask-mode queue -- node path/to/github-mcp-server.js "$@"'
    PowerShellSnippet = '& agentfence mcp proxy --server github --ask-mode queue -- node path/to/github-mcp-server.js @AgentFenceArgs'
    WrapperBase = "agentfence-generic-mcp"
  }
)

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("agentfence-integrations-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

try {
  foreach ($profile in $profiles) {
    $name = $profile.Name
    $actualJson = Invoke-Checked "Render $name JSON profile" {
      & $agentfence integrations show $name --format json
    }
    $examplePath = Join-Path $repoRoot $profile.Example
    $expectedJson = Get-Content -Raw -LiteralPath $examplePath

    if ((Read-CanonicalJson $actualJson) -ne (Read-CanonicalJson $expectedJson)) {
      throw "$name JSON profile differs from $($profile.Example). Regenerate the example or update the built-in profile."
    }

    $shell = Invoke-Checked "Render $name shell wrapper" {
      & $agentfence integrations show $name --format shell
    }
    Assert-Contains $shell $profile.ShellSnippet "$name shell wrapper"

    $powershell = Invoke-Checked "Render $name PowerShell wrapper" {
      & $agentfence integrations show $name --format powershell
    }
    Assert-Contains $powershell $profile.PowerShellSnippet "$name PowerShell wrapper"

    $wrapperDir = Join-Path $tempRoot $name
    Invoke-Checked "Install $name shell wrapper" {
      & $agentfence integrations install $name --format shell --output-dir $wrapperDir --force
    } | Out-Null
    Invoke-Checked "Install $name PowerShell wrapper" {
      & $agentfence integrations install $name --format powershell --output-dir $wrapperDir --force
    } | Out-Null

    $shellPath = Join-Path $wrapperDir $profile.WrapperBase
    $powershellPath = Join-Path $wrapperDir "$($profile.WrapperBase).ps1"
    if (-not (Test-Path -LiteralPath $shellPath)) {
      throw "Missing installed shell wrapper: $shellPath"
    }
    if (-not (Test-Path -LiteralPath $powershellPath)) {
      throw "Missing installed PowerShell wrapper: $powershellPath"
    }
    Assert-Contains (Get-Content -Raw -LiteralPath $shellPath) $profile.ShellSnippet "$name installed shell wrapper"
    Assert-Contains (Get-Content -Raw -LiteralPath $powershellPath) $profile.PowerShellSnippet "$name installed PowerShell wrapper"
  }
}
finally {
  Remove-Item -Recurse -Force -LiteralPath $tempRoot -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "AgentFence integration profile checks passed."
