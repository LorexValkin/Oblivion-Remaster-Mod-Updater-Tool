[CmdletBinding()]
param(
    [switch] $SkipTests
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $RepoRoot

$CargoText = Get-Content -LiteralPath (Join-Path $RepoRoot "Cargo.toml") -Raw
$VersionMatch = [regex]::Match($CargoText, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $VersionMatch.Success) {
    throw "Could not read package version from Cargo.toml"
}
$Version = $VersionMatch.Groups[1].Value
$StageName = "OBR-Mod-Updater-v$Version-windows-x64"
$DistRoot = Join-Path $RepoRoot "dist"
$StageRoot = Join-Path $DistRoot $StageName
$ArchivePath = Join-Path $DistRoot "$StageName.zip"
$ReleaseTarget = Join-Path $RepoRoot ".tmp\release-target-$Version"
$ReleaseBin = Join-Path $ReleaseTarget "release"

if (-not $SkipTests) {
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt gate failed" }
    cargo test
    if ($LASTEXITCODE -ne 0) { throw "cargo test gate failed" }
}

$PreviousCargoTarget = $env:CARGO_TARGET_DIR
$PreviousEncodedRustFlags = $env:CARGO_ENCODED_RUSTFLAGS
$env:CARGO_TARGET_DIR = $ReleaseTarget
$EncodedRustFlags = @()
if (-not [string]::IsNullOrWhiteSpace($PreviousEncodedRustFlags)) {
    $EncodedRustFlags += $PreviousEncodedRustFlags -split [char]0x1f
}
$EncodedRustFlags += "--remap-path-prefix=$RepoRoot=obr-source"
if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $EncodedRustFlags += "--remap-path-prefix=$($env:USERPROFILE)=rust-toolchain"
}
$env:CARGO_ENCODED_RUSTFLAGS = $EncodedRustFlags -join [char]0x1f
try {
    cargo build --release --bins
    $BuildExitCode = $LASTEXITCODE
}
finally {
    $env:CARGO_TARGET_DIR = $PreviousCargoTarget
    $env:CARGO_ENCODED_RUSTFLAGS = $PreviousEncodedRustFlags
}
if ($BuildExitCode -ne 0) { throw "release build failed" }

if (Test-Path -LiteralPath $StageRoot) {
    Remove-Item -LiteralPath $StageRoot -Recurse -Force
}
if (Test-Path -LiteralPath $ArchivePath) {
    Remove-Item -LiteralPath $ArchivePath -Force
}
New-Item -ItemType Directory -Path $StageRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $StageRoot "Dependencies") -Force | Out-Null

$Copies = @(
    @((Join-Path $ReleaseBin "obr-mod-updater.exe"), "OBR Mod Updater.exe"),
    @("packaging\README.txt", "README.txt"),
    @("packaging\Dependencies\PLACE TOOL ARCHIVES HERE.txt", "Dependencies\PLACE TOOL ARCHIVES HERE.txt"),
    @("LICENSE", "LICENSE"),
    @("THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md")
)
foreach ($Copy in $Copies) {
    $Source = if ([IO.Path]::IsPathRooted($Copy[0])) {
        $Copy[0]
    } else {
        Join-Path $RepoRoot $Copy[0]
    }
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required release file missing: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $StageRoot $Copy[1])
}

$SensitiveTokens = @(
    [pscustomobject]@{ Label = "build repository path"; Value = $RepoRoot },
    [pscustomobject]@{ Label = "Windows user profile"; Value = $env:USERPROFILE },
    [pscustomobject]@{ Label = "build computer name"; Value = $env:COMPUTERNAME },
    [pscustomobject]@{ Label = "Git author name"; Value = (git config user.name 2>$null) },
    [pscustomobject]@{ Label = "Git author email"; Value = (git config user.email 2>$null) },
    [pscustomobject]@{ Label = "Git remote URL"; Value = (git config --get remote.origin.url 2>$null) }
) | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_.Value) -and
    $_.Value.Length -ge 6 -and
    -not $_.Value.Equals("Lorex_", [StringComparison]::OrdinalIgnoreCase)
}
foreach ($File in Get-ChildItem -LiteralPath $StageRoot -File -Recurse) {
    $Bytes = [IO.File]::ReadAllBytes($File.FullName)
    $SingleByteText = [Text.Encoding]::Latin1.GetString($Bytes)
    $WideText = [Text.Encoding]::Unicode.GetString($Bytes)
    foreach ($Token in $SensitiveTokens) {
        $SingleByteMatch = $SingleByteText.IndexOf(
            $Token.Value,
            [StringComparison]::OrdinalIgnoreCase
        ) -ge 0
        $WideMatch = $WideText.IndexOf(
            $Token.Value,
            [StringComparison]::OrdinalIgnoreCase
        ) -ge 0
        if ($SingleByteMatch -or $WideMatch) {
            $Relative = [IO.Path]::GetRelativePath($StageRoot, $File.FullName)
            throw "Release privacy gate failed: $Relative contains $($Token.Label)"
        }
    }
}

$Files = Get-ChildItem -LiteralPath $StageRoot -File -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        [ordered]@{
            path = [IO.Path]::GetRelativePath($StageRoot, $_.FullName).Replace("\", "/")
            bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
$Manifest = [ordered]@{
    schema = "obr-release-manifest"
    version = 1
    applicationVersion = $Version
    generatedAt = [DateTime]::UtcNow.ToString("o")
    target = "windows-x86_64"
    runtimeVerified = $false
    finalTwoStaffRelease = $false
    files = @($Files)
}
$Manifest | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $StageRoot "RELEASE-MANIFEST.json") -Encoding utf8

Compress-Archive -LiteralPath $StageRoot -DestinationPath $ArchivePath -CompressionLevel Optimal
Write-Output $ArchivePath
