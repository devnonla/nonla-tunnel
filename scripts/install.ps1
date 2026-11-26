# nonla-tunnel installer — Windows (PowerShell 5.1+).
#
#   $env:NONLA_INVITE='nti_...'; irm https://<domain>/install.ps1 | iex        # from your server
#   irm https://raw.githubusercontent.com/devnonla/nonla-tunnel/main/scripts/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://<domain>/install.ps1))) -Invite nti_...
#
# Parameters (or env vars): -Invite (NONLA_INVITE), -Server (NONLA_SERVER),
# -Version (NONLA_VERSION), -InstallDir (NONLA_INSTALL_DIR), -NoModifyPath.
# NONLA_DOWNLOAD_BASE=URL uses a mirror with <asset> + SHA256SUMS.txt instead of GitHub Releases.
#
# Downloads the release binary for this architecture from GitHub Releases and
# verifies it against the release's SHA256SUMS.txt before installing.
param(
    [string]$Invite = $env:NONLA_INVITE,
    [string]$Server = $env:NONLA_SERVER,
    [string]$Version = $env:NONLA_VERSION,
    [string]$InstallDir = $env:NONLA_INSTALL_DIR,
    [switch]$NoModifyPath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with the progress bar

$Repo = 'devnonla/nonla-tunnel'
# Filled in by the server when served from https://<domain>/install.ps1.
$NonlaDefaultVersion = ''
$NonlaDefaultServer = ''
$NonlaDefaultEnrollFlags = @()

if (-not $Server) { $Server = $NonlaDefaultServer }
if (-not $Version) { $Version = $NonlaDefaultVersion }
if (-not $InstallDir) { $InstallDir = Join-Path $HOME '.nonla-tunnel\bin' }

# --- platform -------------------------------------------------------------
$cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($cpu) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "unsupported architecture: $cpu" }
}
$asset = "nonla-tunnel-windows-$arch.exe"

# --- download + verify ----------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($env:NONLA_DOWNLOAD_BASE) {
    $base = $env:NONLA_DOWNLOAD_BASE.TrimEnd('/')
} elseif ($Version) {
    $base = "https://github.com/$Repo/releases/download/v$($Version.TrimStart('v'))"
} else {
    $base = "https://github.com/$Repo/releases/latest/download"
}
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("nonla-tunnel-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading $asset from $base ..."
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile (Join-Path $tmp 'SHA256SUMS.txt')

    $want = $null
    foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS.txt')) {
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $asset) { $want = $parts[0].ToLower(); break }
    }
    if (-not $want) { throw "$asset is not listed in SHA256SUMS.txt" }
    $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $asset)).Hash.ToLower()
    if ($want -ne $got) { throw "checksum mismatch for $asset (expected $want, got $got)" }
    Write-Host 'Checksum OK'

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $bin = Join-Path $InstallDir 'nonla-tunnel.exe'
    # A running nonla-tunnel.exe cannot be overwritten; move it aside first.
    if (Test-Path $bin) {
        $old = Join-Path $InstallDir 'nonla-tunnel.old.exe'   # removed by nonla-tunnel on next start
        Remove-Item -Force $old -ErrorAction SilentlyContinue
        Move-Item -Force $bin $old
    }
    Move-Item -Force (Join-Path $tmp $asset) $bin
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
Write-Host "Installed $(& $bin --version) -> $bin"

# --- PATH -----------------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @($userPath -split ';' | Where-Object { $_ })
if (-not $NoModifyPath -and -not ($parts -contains $InstallDir)) {
    [Environment]::SetEnvironmentVariable('Path', (($parts + $InstallDir) -join ';'), 'User')
    Write-Host "Added $InstallDir to your user PATH (new terminals pick it up)"
}
if (-not (($env:Path -split ';') -contains $InstallDir)) { $env:Path = "$InstallDir;$env:Path" }

# --- enroll ---------------------------------------------------------------
if ($Invite) {
    if (-not $Server) { throw '-Invite needs -Server connect.<domain> (or install from https://<domain>/install.ps1)' }
    Write-Host 'Enrolling with one-time invite...'
    # Passed via env so the invite does not show up in process listings.
    $env:NONLA_INVITE = $Invite
    try {
        & $bin enroll --server $Server @NonlaDefaultEnrollFlags
        if ($LASTEXITCODE -ne 0) { throw "enroll failed (exit $LASTEXITCODE)" }
    } finally {
        Remove-Item Env:\NONLA_INVITE -ErrorAction SilentlyContinue
    }
} else {
    $srv = if ($Server) { $Server } else { 'connect.<domain>' }
    Write-Host ''
    Write-Host 'Next:'
    Write-Host "  nonla-tunnel enroll --server $srv --invite <nti_...>"
    Write-Host '  nonla-tunnel http 3000 --name my-app -d'
}
