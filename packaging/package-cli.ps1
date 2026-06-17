param(
  [Parameter(Mandatory = $true)]
  [string]$Name,
  [string]$ExeSuffix = "",
  [string]$TargetDir = "target/release",
  [string]$DistDir = "dist",
  [string]$Version = $env:GITHUB_REF_NAME,
  [string]$Repository = $env:GITHUB_REPOSITORY,
  [string]$Commit = $env:GITHUB_SHA
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$RepoRoot = $RepoRoot.Path

function Resolve-RepoPath {
  param([string]$Path)

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }

  return Join-Path $RepoRoot $Path
}

$TargetDir = Resolve-RepoPath $TargetDir
$DistDir = Resolve-RepoPath $DistDir

$AgentFence = Join-Path $TargetDir "agentfence$ExeSuffix"
$AgentFenced = Join-Path $TargetDir "agentfenced$ExeSuffix"

if (!(Test-Path -LiteralPath $AgentFence -PathType Leaf)) {
  throw "Missing built CLI binary: $AgentFence"
}
if (!(Test-Path -LiteralPath $AgentFenced -PathType Leaf)) {
  throw "Missing built daemon binary: $AgentFenced"
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$StageDir = Join-Path $DistDir "agentfence-$Name"
$ArchivePath = Join-Path $DistDir "agentfence-$Name.zip"
$ManifestPath = Join-Path $DistDir "agentfence-$Name.checksums.json"

Remove-Item -Recurse -Force -LiteralPath $StageDir -ErrorAction SilentlyContinue
Remove-Item -Force -LiteralPath $ArchivePath -ErrorAction SilentlyContinue
Remove-Item -Force -LiteralPath $ManifestPath -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
Copy-Item -LiteralPath $AgentFence -Destination $StageDir -Force
Copy-Item -LiteralPath $AgentFenced -Destination $StageDir -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "README.md") -Destination $StageDir -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "agentfence.policy.json") -Destination $StageDir -Force
$PackagingDir = Join-Path $RepoRoot "packaging"
Copy-Item -LiteralPath (Join-Path $PackagingDir "install.ps1") -Destination $StageDir -Force
Copy-Item -LiteralPath (Join-Path $PackagingDir "install.sh") -Destination $StageDir -Force

Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ArchivePath -Force

& (Join-Path $PSScriptRoot "release-manifest.ps1") `
  -ArtifactPath $ArchivePath `
  -ArtifactDir $DistDir `
  -Output $ManifestPath `
  -Version $Version `
  -Repository $Repository `
  -Commit $Commit

Write-Host "Packaged $ArchivePath"
