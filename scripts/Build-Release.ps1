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
$StandaloneExePath = Join-Path $DistRoot "$StageName.exe"
$ChecksumsPath = Join-Path $DistRoot "$StageName-SHA256SUMS.txt"
$ReleaseBodyPath = Join-Path $DistRoot "$StageName-RELEASE-NOTES.md"
$ReleaseNotesPath = Join-Path $RepoRoot "docs\NEXUS-$Version-BETA.md"
$ReleaseTarget = Join-Path $RepoRoot ".tmp\release-target-$Version"
$ReleaseBin = Join-Path $ReleaseTarget "release"

function Get-SafeRelativePath {
    param(
        [Parameter(Mandatory = $true)][string] $BasePath,
        [Parameter(Mandatory = $true)][string] $TargetPath
    )
    $BaseFull = [IO.Path]::GetFullPath($BasePath).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $TargetFull = [IO.Path]::GetFullPath($TargetPath)
    $Prefix = $BaseFull + [IO.Path]::DirectorySeparatorChar
    if (-not $TargetFull.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release file is outside the staging root: $TargetFull"
    }
    return $TargetFull.Substring($Prefix.Length)
}

if (-not (Test-Path -LiteralPath $ReleaseNotesPath -PathType Leaf)) {
    throw "Version-specific release notes missing: $ReleaseNotesPath"
}

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
if (Test-Path -LiteralPath $StandaloneExePath) {
    Remove-Item -LiteralPath $StandaloneExePath -Force
}
if (Test-Path -LiteralPath $ChecksumsPath) {
    Remove-Item -LiteralPath $ChecksumsPath -Force
}
if (Test-Path -LiteralPath $ReleaseBodyPath) {
    Remove-Item -LiteralPath $ReleaseBodyPath -Force
}
New-Item -ItemType Directory -Path $StageRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $StageRoot "Dependencies") -Force | Out-Null

$Copies = @(
    @((Join-Path $ReleaseBin "obr-mod-updater.exe"), "OBR Mod Updater.exe"),
    @($ReleaseNotesPath, "WHATS-NEW.md"),
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

$StagedExe = Join-Path $StageRoot "OBR Mod Updater.exe"
$ExecutableVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($StagedExe)
$ExpectedExecutableVersion = "^$([regex]::Escape($Version))(?:\.0)?(?:\s|$)"
foreach ($VersionField in @(
    [pscustomobject]@{ Label = "FileVersion"; Value = $ExecutableVersion.FileVersion },
    [pscustomobject]@{ Label = "ProductVersion"; Value = $ExecutableVersion.ProductVersion }
)) {
    if ([string]::IsNullOrWhiteSpace($VersionField.Value) -or
        $VersionField.Value -notmatch $ExpectedExecutableVersion) {
        throw "Release version gate failed: EXE $($VersionField.Label) '$($VersionField.Value)' does not match Cargo version '$Version'"
    }
}

$SensitiveTokens = @(
    [pscustomobject]@{ Label = "build repository path"; Value = $RepoRoot },
    [pscustomobject]@{ Label = "Windows user profile"; Value = $env:USERPROFILE },
    [pscustomobject]@{ Label = "build computer name"; Value = $env:COMPUTERNAME },
    [pscustomobject]@{ Label = "Git author name"; Value = (git config user.name 2>$null) },
    [pscustomobject]@{ Label = "Git author email"; Value = (git config user.email 2>$null) },
    [pscustomobject]@{ Label = "Git remote URL"; Value = (git config --get remote.origin.url 2>$null) }
) | Where-Object {
    $TokenValue = [string]$_.Value
    -not [string]::IsNullOrWhiteSpace($TokenValue) -and
    $TokenValue.Length -ge 6 -and
    -not [string]::Equals($TokenValue, "Lorex_", [StringComparison]::OrdinalIgnoreCase)
}
foreach ($File in Get-ChildItem -LiteralPath $StageRoot -File -Recurse) {
    $Bytes = [IO.File]::ReadAllBytes($File.FullName)
    # Encoding.Latin1 is unavailable in Windows PowerShell's older .NET runtime.
    $SingleByteText = [Text.Encoding]::GetEncoding(28591).GetString($Bytes)
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
            $Relative = Get-SafeRelativePath -BasePath $StageRoot -TargetPath $File.FullName
            throw "Release privacy gate failed: $Relative contains $($Token.Label)"
        }
    }
}

$Files = Get-ChildItem -LiteralPath $StageRoot -File -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        [ordered]@{
            path = (Get-SafeRelativePath -BasePath $StageRoot -TargetPath $_.FullName).Replace("\", "/")
            bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
$Manifest = [ordered]@{
    schema = "obr-release-manifest"
    version = 1
    applicationVersion = $Version
    executableFileVersion = $ExecutableVersion.FileVersion
    executableProductVersion = $ExecutableVersion.ProductVersion
    generatedAt = [DateTime]::UtcNow.ToString("o")
    target = "windows-x86_64"
    runtimeVerified = $false
    finalTwoStaffRelease = $false
    files = @($Files)
}
$Manifest | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $StageRoot "RELEASE-MANIFEST.json") -Encoding utf8

Compress-Archive -LiteralPath $StageRoot -DestinationPath $ArchivePath -CompressionLevel Optimal
Copy-Item -LiteralPath $StagedExe -Destination $StandaloneExePath
$ChecksumRows = @(
    ("{0}  {1}" -f (Get-FileHash -LiteralPath $StandaloneExePath -Algorithm SHA256).Hash.ToLowerInvariant(), [IO.Path]::GetFileName($StandaloneExePath))
    ("{0}  {1}" -f (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant(), [IO.Path]::GetFileName($ArchivePath))
)
$ChecksumRows | Set-Content -LiteralPath $ChecksumsPath -Encoding ascii
$ReleaseBody = (Get-Content -LiteralPath $ReleaseNotesPath -Raw).TrimEnd()
$ReleaseBody += "`r`n`r`n## SHA-256 checksums`r`n`r`n"
$ReleaseBody += "- EXE: ``$($ChecksumRows[0].Split(' ')[0])```r`n"
$ReleaseBody += "- ZIP: ``$($ChecksumRows[1].Split(' ')[0])```r`n"
$ReleaseBody | Set-Content -LiteralPath $ReleaseBodyPath -Encoding utf8
Write-Output $StandaloneExePath
Write-Output $ArchivePath
Write-Output $ChecksumsPath
Write-Output $ReleaseBodyPath
