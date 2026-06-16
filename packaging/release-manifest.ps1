param(
  [string[]]$ArtifactPath = @(),
  [string]$ArtifactDir = "dist",
  [string]$Output = "dist/agentfence-checksums.json",
  [string]$Version = $env:GITHUB_REF_NAME,
  [string]$Repository = $env:GITHUB_REPOSITORY,
  [string]$Commit = $env:GITHUB_SHA
)

$ErrorActionPreference = "Stop"

function Resolve-ArtifactFiles {
  if ($ArtifactPath.Count -gt 0) {
    foreach ($item in $ArtifactPath) {
      if (!(Test-Path -LiteralPath $item -PathType Leaf)) {
        throw "Artifact path does not exist or is not a file: $item"
      }
      Get-Item -LiteralPath $item
    }
    return
  }

  if (!(Test-Path -LiteralPath $ArtifactDir -PathType Container)) {
    throw "Artifact directory does not exist: $ArtifactDir"
  }

  $outputFullPath = $null
  if (Test-Path -LiteralPath $Output) {
    $outputFullPath = (Resolve-Path -LiteralPath $Output).Path
  }

  Get-ChildItem -LiteralPath $ArtifactDir -File -Recurse |
    Where-Object { $null -eq $outputFullPath -or $_.FullName -ne $outputFullPath }
}

function Get-RelativeArtifactPath {
  param([System.IO.FileInfo]$File)

  if (Test-Path -LiteralPath $ArtifactDir -PathType Container) {
    $root = (Resolve-Path -LiteralPath $ArtifactDir).Path
    $rootFullPath = [System.IO.Path]::GetFullPath($root)
    if (!$rootFullPath.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
      $rootFullPath = "$rootFullPath$([System.IO.Path]::DirectorySeparatorChar)"
    }
    $rootUri = New-Object System.Uri($rootFullPath)
    $fileUri = New-Object System.Uri([System.IO.Path]::GetFullPath($File.FullName))
    return [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($fileUri).ToString()).Replace("\", "/")
  }

  return $File.Name
}

$files = @(Resolve-ArtifactFiles | Sort-Object FullName)
if ($files.Count -eq 0) {
  throw "No release artifacts found for manifest generation."
}

$artifacts = foreach ($file in $files) {
  $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
  [ordered]@{
    path = Get-RelativeArtifactPath -File $file
    name = $file.Name
    size = $file.Length
    sha256 = $hash.Hash.ToLowerInvariant()
  }
}

$manifest = [ordered]@{
  kind = "agentfence.releaseManifest"
  version = "0.1"
  generatedAt = (Get-Date).ToUniversalTime().ToString("o")
  release = [ordered]@{
    version = $Version
    repository = $Repository
    commit = $Commit
  }
  artifacts = @($artifacts)
}

$outputDirectory = Split-Path -Parent $Output
if (![string]::IsNullOrWhiteSpace($outputDirectory)) {
  New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}

$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $Output -Encoding UTF8
Write-Host "Wrote release manifest to $Output"
