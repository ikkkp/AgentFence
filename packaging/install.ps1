param(
  [string]$InstallDir = "$env:LOCALAPPDATA\AgentFence\bin",
  [switch]$SkipPath
)

$ErrorActionPreference = "Stop"
$PackageDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentFence = Join-Path $PackageDir "agentfence.exe"
$AgentFenced = Join-Path $PackageDir "agentfenced.exe"

if (!(Test-Path -LiteralPath $AgentFence) -or !(Test-Path -LiteralPath $AgentFenced)) {
  throw "Run this script from an AgentFence release archive containing agentfence.exe and agentfenced.exe."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -LiteralPath $AgentFence -Destination (Join-Path $InstallDir "agentfence.exe") -Force
Copy-Item -LiteralPath $AgentFenced -Destination (Join-Path $InstallDir "agentfenced.exe") -Force

if (!$SkipPath) {
  $current = [Environment]::GetEnvironmentVariable("Path", "User")
  if ([string]::IsNullOrWhiteSpace($current)) {
    $parts = @()
  } else {
    $parts = $current -split ";" | Where-Object { $_ -ne "" }
  }

  if (-not ($parts | Where-Object { $_ -ieq $InstallDir })) {
    $next = ($parts + $InstallDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $next, "User")
    Write-Host "Added $InstallDir to the user PATH. Open a new terminal before running agentfence."
  } else {
    Write-Host "$InstallDir is already on the user PATH."
  }
}

Write-Host "Installed AgentFence CLI to $InstallDir"
