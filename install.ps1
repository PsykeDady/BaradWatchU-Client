#Requires -Version 5.1
# BaradWatchU Client installer for Windows: the Windows counterpart of install.sh.
# Per-user installation, no administrator rights, no service. Run it with:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 [options]
# -Package builds the same artifacts into a per-user setup.exe with Inno Setup 6.
param(
    [Alias('h')][switch]$Help,
    [Alias('V')][switch]$Version,
    [switch]$MissingDeps,
    [switch]$DryRun,
    [switch]$NoBuild,
    [switch]$BuildOnly,
    [string]$BuildDir = '',
    [string]$Prefix = '',
    [Alias('U')][switch]$Uninstall,
    [switch]$WithoutTray,
    [switch]$TrayAutostart,
    [switch]$NoTrayAutostart,
    [switch]$Package,
    [string]$OutputDir = ''
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$Product = 'Client'
$Bin = 'baradwatchu-agent.exe'
$TrayBin = 'baradwatchu-tray.exe'
$Root = $PSScriptRoot
$ManifestHeader = 'BaradWatchU source manifest v1'
$ManifestKind = 'client-windows'
$MarkerHeader = 'BaradWatchU build marker v2-windows'
$Platform = 'Windows-x64'
# Inno Setup AppId of the setup.exe produced by -Package (packaging/windows/baradwatchu-client.iss).
$SetupAppId = '{8F3D2B6A-4C1E-4B7A-9E52-6D0B1C7A3E94}'
$StartMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\BaradWatchU'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValue = 'BaradWatchU-Tray'

function Show-Usage {
    @'
BaradWatchU Client installer for Windows (per user, no administrator rights)
Usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 [OPTIONS]
  -Help, -h          Show help          -Version, -V       Show version
  -MissingDeps       Read-only dependency check: [REQUIRED] items block the
                     install, [optional] items only degrade checks or packaging
  -DryRun            Print the plan without changing files
  -NoBuild           Reuse a validated source/platform/version build cache
  -BuildOnly         Build and validate the cache; do not install files
  -BuildDir DIR      Build cache outside the source tree
                     (default %LOCALAPPDATA%\baradwatchu\build\baradwatchu-agent-VERSION)
  -Prefix DIR        Installation folder (default %LOCALAPPDATA%\Programs\BaradWatchU)
  -Uninstall, -U     Remove unchanged files listed in the installation manifest
  -WithoutTray       Do not build/install the baradwatchu-tray companion
  -TrayAutostart     Enable start of the tray at login (HKCU Run key), also on a reinstall
  -NoTrayAutostart   Do not enable it on a first installation. By default a first
                     installation enables start at login and a reinstall keeps the
                     user's choice (tray menu: Avvia al login)
  -Package           Build a per-user setup.exe with Inno Setup 6 instead of
                     installing (with -OutputDir DIR, default BUILDDIR\dist)
Everything runs as the current user: files go to a per-user folder and Start
menu entries to the user's Start menu. No service, scheduled task or system
setting is changed; settings, custom checks and history are never touched.
Before files are replaced or removed, a running baradwatchu-agent or
baradwatchu-tray of the same installation (matched by executable path, e.g. an
open dashboard) is asked to close (Ctrl+C / close request) and gets up to
BARADWATCHU_STOP_TIMEOUT seconds (default 10); it is never killed.
'@
}

function Fail([string]$Message) {
    Write-Host "Error: $Message" -ForegroundColor Red
    exit 1
}
function BadArg([string]$Message) {
    Write-Host "Error: $Message" -ForegroundColor Red
    Show-Usage
    exit 2
}
function Section([string]$Text) { Write-Host ''; Write-Host $Text -ForegroundColor White }
function DepOk([string]$Text) { Write-Host '  [ok]        ' -ForegroundColor Green -NoNewline; Write-Host $Text }
function DepRequired([string]$Text) { Write-Host '  [REQUIRED]  ' -ForegroundColor Red -NoNewline; Write-Host $Text }
function DepOptional([string]$Text) { Write-Host '  [optional]  ' -ForegroundColor Yellow -NoNewline; Write-Host $Text }
function DepNote([string]$Text) { Write-Host "  $Text" -ForegroundColor DarkGray }

# --- version and paths -------------------------------------------------------------------

function Get-WorkspaceVersion {
    $inPackage = $false
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $Root 'Cargo.toml'))) {
        if ($line -match '^\s*\[workspace\.package\]') { $inPackage = $true; continue }
        if ($line -match '^\s*\[') { $inPackage = $false }
        if ($inPackage -and $line -match '^\s*version\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    return ''
}
$ProductVersion = Get-WorkspaceVersion
if ($ProductVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    Write-Host 'Error: Invalid SemVer in Cargo.toml' -ForegroundColor Red; exit 1
}

function Get-FullPath([string]$Path) { return [IO.Path]::GetFullPath($Path).TrimEnd('\') }
function Test-Inside([string]$Path, [string]$Parent) {
    $p = (Get-FullPath $Path) + '\'
    $q = (Get-FullPath $Parent) + '\'
    return $p.StartsWith($q, [StringComparison]::OrdinalIgnoreCase)
}
# Symbolic links and junctions are refused along the installation path (same boundary as
# install.sh, which refuses symlinked or foreign-writable parents).
function Assert-NoReparsePoint([string]$Path) {
    $current = Get-FullPath $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "symbolic link or junction in installation path: $current" }
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
}

# --- dependencies ------------------------------------------------------------------------

function Test-AtLeast([string]$Have, [string]$Need) {
    try { return ([version]$Have) -ge ([version]$Need) } catch { return $false }
}
function Get-InnoCompiler {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    foreach ($candidate in $candidates) { if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate } }
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

# Mode: audit (-MissingDeps: report everything), build, runtime (-NoBuild), package.
function Test-Dependencies([string]$Mode) {
    $missing = 0
    $build = $Mode -in @('audit', 'build', 'package')
    if ($build) {
        Section '[REQUIRED] build tools'
        $needRust = if ($WithoutTray) { '1.80.0' } else { '1.92.0' }
        $rustc = Get-Command rustc -ErrorAction SilentlyContinue
        $cargo = Get-Command cargo -ErrorAction SilentlyContinue
        $rustVersion = ''
        if ($rustc) { $rustVersion = ((& $rustc.Source --version) -replace '^rustc\s+(\S+).*$', '$1') -replace '-.*$', '' }
        if ($cargo -and $rustc -and (Test-AtLeast $rustVersion $needRust)) { DepOk "Rust/Cargo $rustVersion (>= $needRust)" }
        else { DepRequired "Rust/Cargo >= $needRust with the MSVC toolchain (winget install Rustlang.Rustup)"; $missing++ }
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $msvc = $null
        if (Test-Path -LiteralPath $vswhere) {
            $msvc = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        }
        if ($msvc) { DepOk "MSVC C++ build tools ($msvc)" }
        else { DepRequired 'Visual Studio Build Tools with the C++ workload (winget install Microsoft.VisualStudio.2022.BuildTools, workload VCTools)'; $missing++ }
        $node = Get-Command node -ErrorAction SilentlyContinue
        $nodeVersion = ''
        if ($node) { $nodeVersion = (& $node.Source -p 'process.versions.node') }
        if ($node -and $nodeVersion -like '20.*' -and (Test-AtLeast $nodeVersion '20.11.1')) { DepOk "Node.js $nodeVersion" }
        else { DepRequired "Node.js 20 >= 20.11.1 (found: $(if ($nodeVersion) { $nodeVersion } else { 'none' }); winget install OpenJS.NodeJS.20)"; $missing++ }
        if (Get-Command npm -ErrorAction SilentlyContinue) { DepOk 'npm' } else { DepRequired 'npm (installed with Node.js)'; $missing++ }
        if (Get-Command robocopy.exe -ErrorAction SilentlyContinue) { DepOk 'robocopy' } else { DepRequired 'robocopy (part of Windows)'; $missing++ }
    }
    Section '[REQUIRED] runtime'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $powershell) { DepOk "Windows PowerShell 5.1 ($powershell): runs the built-in checks" }
    else { DepRequired 'Windows PowerShell 5.1 (runs the built-in checks)'; $missing++ }
    if ([Environment]::Is64BitOperatingSystem) { DepOk '64-bit Windows' } else { DepRequired '64-bit Windows'; $missing++ }
    if ($Mode -eq 'package' -or $Mode -eq 'audit') {
        $iscc = Get-InnoCompiler
        if ($Mode -eq 'package') {
            Section '[REQUIRED] packaging'
            if ($iscc) { DepOk "Inno Setup 6 ($iscc)" } else { DepRequired 'Inno Setup 6 (winget install JRSoftware.InnoSetup)'; $missing++ }
        } else {
            Section '[optional] packaging (-Package)'
            if ($iscc) { DepOk "Inno Setup 6 ($iscc)" } else { DepOptional 'Inno Setup 6 for -Package (winget install JRSoftware.InnoSetup)' }
        }
    }
    if ($Mode -eq 'audit') {
        Section '[optional] audit sources'
        $mode = $ExecutionContext.SessionState.LanguageMode
        if ("$mode" -eq 'FullLanguage') { DepOk 'PowerShell FullLanguage mode: REQ-008/REQ-009 can call system APIs' }
        else { DepOptional "PowerShell language mode ${mode}: REQ-008/REQ-009 cannot call system APIs and report WARN" }
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { DepOk 'Microsoft Defender cmdlets (REQ-002)' } else { DepOptional 'Microsoft Defender cmdlets (REQ-002 falls back to Security Center)' }
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) { DepOk 'NetSecurity cmdlets (REQ-003)' } else { DepOptional 'NetSecurity cmdlets (REQ-003)' }
        $cato = Join-Path ${env:ProgramFiles(x86)} 'Cato Networks\Cato Client\CatoClientCliAT.exe'
        if (Test-Path -LiteralPath $cato) { DepOk 'Cato Client (REQ-005)' } else { DepOptional 'Cato Client (REQ-005 reports FAIL without it)' }
        DepNote 'A missing optional item never blocks the installation; its check reports WARN or FAIL.'
    }
    return ($missing -eq 0)
}

# --- fingerprints, cache marker and validation -------------------------------------------

function Get-TreeFingerprint([string]$Base, [string[]]$Paths, [string[]]$SkipDirs) {
    $entries = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $Paths) {
        $full = Join-Path $Base $relative
        if (-not (Test-Path -LiteralPath $full)) { continue }
        $item = Get-Item -LiteralPath $full -Force
        if (-not $item.PSIsContainer) { $entries.Add($relative.Replace('\', '/') + "`t" + (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash); continue }
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($full)
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            foreach ($child in Get-ChildItem -LiteralPath $dir -Force) {
                if ($child.PSIsContainer) {
                    if ($SkipDirs -notcontains $child.Name) { $stack.Push($child.FullName) }
                } else {
                    $rel = $child.FullName.Substring($Base.Length).TrimStart('\').Replace('\', '/')
                    $entries.Add($rel + "`t" + (Get-FileHash -Algorithm SHA256 -LiteralPath $child.FullName).Hash)
                }
            }
        }
    }
    $sorted = [string[]]$entries.ToArray()
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $bytes = [Text.Encoding]::UTF8.GetBytes(($sorted -join "`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
}
function Get-SourceFingerprint {
    return Get-TreeFingerprint $Root @('Cargo.toml', 'Cargo.lock', 'install.ps1', 'install.sh', '.cargo', 'crates', 'catalog', 'web', 'packaging') @('.git', 'target', 'node_modules', 'dist', '.angular', 'out-tsc')
}
function Get-ArtifactFingerprint {
    $paths = @("cargo-target\release\$Bin", 'cargo-target\share\baradwatchu-client\catalog', 'angular\browser')
    if (Test-Path -LiteralPath (Join-Path $BuildDir "cargo-target\release\$TrayBin")) { $paths += "cargo-target\release\$TrayBin" }
    return Get-TreeFingerprint $BuildDir $paths @()
}
function Read-Marker {
    $path = Join-Path $BuildDir '.baradwatchu-build'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $lines = [IO.File]::ReadAllLines($path)
    if ($lines.Count -lt 1 -or $lines[0] -ne $MarkerHeader) { return $null }
    $values = @{}
    foreach ($line in $lines | Select-Object -Skip 1) { $i = $line.IndexOf('='); if ($i -gt 0) { $values[$line.Substring(0, $i)] = $line.Substring($i + 1) } }
    return $values
}
function Test-WebVersion {
    $web = Join-Path $Root 'web'
    $packageVersion = (Get-Content -Raw (Join-Path $web 'package.json') | ConvertFrom-Json).version
    $lockVersion = (Get-Content -Raw (Join-Path $web 'package-lock.json') | ConvertFrom-Json).version
    $appVersion = ''
    $match = Select-String -Path (Join-Path $web 'src\app-version.ts') -Pattern "^export const APP_VERSION = '([^']*)';"
    if ($match) { $appVersion = $match.Matches[0].Groups[1].Value }
    return ($packageVersion -eq $ProductVersion -and $lockVersion -eq $ProductVersion -and $appVersion -eq $ProductVersion)
}

# Built-in Windows checks: the trusted manifest (platform "windows") lists every file of every
# check folder. Each listed file must be installed with that hash, nothing unlisted may sit in
# the check folders, and each configuration references only listed files (toolPath with a
# matching expectedSha256, or providers without expectedSha256).
function Test-RequirementAssets([string]$ShareRoot) {
    $catalog = Join-Path $ShareRoot 'catalog'
    $checks = Join-Path $catalog 'checks-windows'
    $digest = Join-Path $catalog 'builtin-tools.sha256'
    if (-not (Test-Path -LiteralPath $checks -PathType Container)) { return 'check folders missing' }
    if (-not (Test-Path -LiteralPath $digest -PathType Leaf)) { return 'builtin hash manifest missing' }
    $entries = @{}
    $ids = @{}
    foreach ($line in [IO.File]::ReadAllLines($digest)) {
        if (-not $line.Trim()) { continue }
        $fields = $line.Trim() -split '\s+'
        if ($fields.Count -ne 4 -or $fields[3] -notmatch '^[0-9a-f]{64}$') { return 'invalid builtin hash entry' }
        if ($fields[1] -ne 'windows') { continue }
        $path = $fields[2]
        if (-not $path.StartsWith("catalog/checks-windows/$($fields[0])/") -or $path -match '(^|/)\.\.(/|$)' -or $entries.ContainsKey($path)) { return "invalid builtin hash path: $path" }
        $entries[$path] = $fields[3]
        $ids[$fields[0]] = $true
    }
    foreach ($path in $entries.Keys) {
        $file = Join-Path $ShareRoot ($path -replace '/', '\')
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return "builtin check file missing: $path" }
        if ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return "builtin check file is a link: $path" }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant() -ne $entries[$path]) { return "builtin hash manifest mismatch: $path" }
    }
    $prefixLength = (Resolve-Path -LiteralPath $ShareRoot).ProviderPath.TrimEnd('\').Length + 1
    foreach ($item in Get-ChildItem -LiteralPath $checks -Recurse -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "link in check folders: $($item.Name)" }
        if ($item.PSIsContainer) { continue }
        $relative = $item.FullName.Substring($prefixLength) -replace '\\', '/'
        if (-not $entries.ContainsKey($relative)) { return "unlisted file in check folders: $relative" }
    }
    $found = @{}
    foreach ($folder in Get-ChildItem -LiteralPath $checks -Force) {
        if (-not $folder.PSIsContainer) { return "unexpected file in check folders: $($folder.Name)" }
        $configPath = Join-Path $folder.FullName 'configuration.json'
        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { return "configuration missing: $($folder.Name)" }
        $config = [IO.File]::ReadAllText($configPath) | ConvertFrom-Json
        if ($config.id -ne $folder.Name -or $config.schemaVersion -ne 'baradwatchu.custom-checks.v1') { return "invalid check configuration identity: $($folder.Name)" }
        $prefix = "catalog/checks-windows/$($folder.Name)/"
        $tool = if ($config.PSObject.Properties['toolPath']) { "$($config.toolPath)" } else { '' }
        $providers = if ($config.PSObject.Properties['providers'] -and $config.providers) { @($config.providers.PSObject.Properties) } else { @() }
        if ($tool -and $providers.Count -eq 0) {
            if ([IO.Path]::IsPathRooted($tool) -or $tool -match '(^|[\\/])\.\.([\\/]|$)') { return "unsafe relative tool path: $($folder.Name)" }
            $expected = $prefix + ($tool -replace '^\./', '')
            if (-not $entries.ContainsKey($expected) -or $config.expectedSha256 -ne $entries[$expected]) { return "builtin tool hash manifest mismatch: $($folder.Name)" }
        } elseif (-not $tool -and $providers.Count -gt 0 -and -not $config.PSObject.Properties['expectedSha256']) {
            foreach ($provider in $providers) {
                $path = "$($provider.Value.toolPath)"
                if (-not $path -or [IO.Path]::IsPathRooted($path) -or $path -match '(^|[\\/])\.\.([\\/]|$)') { return "unsafe provider path: $($folder.Name)" }
                if (-not $entries.ContainsKey($prefix + ($path -replace '^\./', ''))) { return "provider not in builtin hash manifest: $($folder.Name)/$($provider.Name)" }
            }
        } else {
            return "check configuration needs toolPath or providers: $($folder.Name)"
        }
        $found[$folder.Name] = $true
    }
    if ($found.Count -eq 0 -or $found.Count -ne $ids.Count) { return 'builtin hash manifest does not match discovered folders' }
    foreach ($id in $ids.Keys) { if (-not $found.ContainsKey($id)) { return "builtin check folder missing: $id" } }
    return $null
}

function Test-Build {
    $marker = Read-Marker
    if (-not $marker) { Fail "no current build cache at $BuildDir; rebuild (for example with -BuildOnly -BuildDir DIR)" }
    if ($marker['product'] -ne 'client' -or $marker['state'] -ne 'complete' -or $marker['platform'] -ne $Platform -or $marker['version'] -ne $ProductVersion) {
        Fail 'build cache is for another product, platform or version; rebuild'
    }
    if ($marker['fingerprint'] -ne (Get-SourceFingerprint)) { Fail 'sources changed since the cached build; rebuild' }
    $agent = Join-Path $BuildDir "cargo-target\release\$Bin"
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { Fail 'build cache has no agent binary; rebuild' }
    if (-not $WithoutTray) {
        if ($marker['tray'] -ne '1' -or -not (Test-Path -LiteralPath (Join-Path $BuildDir "cargo-target\release\$TrayBin") -PathType Leaf)) {
            Fail 'build cache has no tray companion; rebuild, or install with -WithoutTray'
        }
    }
    $problem = Test-RequirementAssets (Join-Path $BuildDir 'cargo-target\share\baradwatchu-client')
    if ($problem) { Fail "cached check folders or trusted builtin hashes are incomplete or unsafe ($problem); rebuild" }
    $browser = Join-Path $BuildDir 'angular\browser'
    if (-not (Test-Path -LiteralPath (Join-Path $browser 'index.html') -PathType Leaf)) { Fail 'Angular assets incomplete' }
    if (-not (Get-ChildItem -LiteralPath $browser -Filter *.js -Recurse | Select-Object -First 1)) { Fail 'Angular JavaScript bundle missing' }
    if ($marker['artifacts'] -ne (Get-ArtifactFingerprint)) { Fail 'cached artifacts changed; rebuild with -BuildOnly' }
    Write-Host "Validated build $BuildDir ($Platform, $ProductVersion)"
}

## The tray is a GUI-subsystem program on Windows: PowerShell waits for it, captures its output
## and sets its exit code only when its output goes through a pipeline.
function Invoke-Tray([string]$Path, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $text = (& $Path @Arguments 2>&1 | Out-String).Trim() }
    finally { $ErrorActionPreference = $previous }
    return @{ Text = $text; Code = $LASTEXITCODE }
}

function Invoke-Native([string]$What, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) { Fail "$What failed (exit code $LASTEXITCODE)" }
}

# Remove-Item fails on paths longer than 260 characters (deep node_modules): empty the tree
# with robocopy /MIR first, which handles long paths, then remove the empty folders.
function Remove-Tree([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $empty = Join-Path $BuildDir ('empty-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $empty | Out-Null
    try {
        & robocopy.exe $empty $Path /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
        Remove-Item -LiteralPath $Path -Recurse -Force
    } finally {
        Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Build {
    if (-not (Test-Dependencies 'build')) { Fail 'required build dependencies are missing (see the [REQUIRED] items above); nothing was built or installed' }
    if (-not (Test-WebVersion)) { Fail 'web package versions differ from Cargo.toml; run npm run sync-version in web' }
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    Assert-NoReparsePoint $BuildDir
    $markerPath = Join-Path $BuildDir '.baradwatchu-build'
    if (Test-Path -LiteralPath $markerPath) { Remove-Item -LiteralPath $markerPath -Force }
    $before = Get-SourceFingerprint
    $previousTarget = $env:CARGO_TARGET_DIR
    $env:CARGO_TARGET_DIR = Join-Path $BuildDir 'cargo-target'
    Push-Location $Root
    try {
        if ($WithoutTray) {
            Invoke-Native 'cargo build' { cargo build --release -p baradwatchu-agent --locked }
            # A tray binary from an earlier build must not be installed or fingerprinted.
            $stale = Join-Path $BuildDir "cargo-target\release\$TrayBin"
            if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
        } else {
            Invoke-Native 'cargo build' { cargo build --release --workspace --locked }
        }
    } finally {
        Pop-Location
        $env:CARGO_TARGET_DIR = $previousTarget
    }
    # npm ci removes node_modules: build in a private copy, never in the checkout.
    $webSource = Join-Path $BuildDir 'web-source'
    Remove-Tree $webSource
    New-Item -ItemType Directory -Force -Path $webSource | Out-Null
    Copy-Item -LiteralPath (Join-Path $Root 'Cargo.toml') -Destination (Join-Path $webSource 'Cargo.toml')
    & robocopy.exe (Join-Path $Root 'web') (Join-Path $webSource 'web') /E /XD node_modules dist .angular out-tsc /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Fail "copy of the web sources failed (robocopy $LASTEXITCODE)" }
    $angular = Join-Path $BuildDir 'angular'
    Remove-Tree $angular
    $previousCache = $env:npm_config_cache
    if (-not $env:npm_config_cache) { $env:npm_config_cache = Join-Path $BuildDir 'npm-cache' }
    Push-Location (Join-Path $webSource 'web')
    try {
        Invoke-Native 'npm ci' { npm ci --no-audit --no-fund }
        Invoke-Native 'npm run build' { npm run build -- "--output-path=$angular" }
    } finally {
        Pop-Location
        $env:npm_config_cache = $previousCache
        try { Remove-Tree $webSource } catch { Write-Host "Warning: could not remove $webSource" -ForegroundColor Yellow }
    }
    if ($before -ne (Get-SourceFingerprint)) { Fail 'sources changed during build; retry with a stable checkout' }
    $agent = Join-Path $BuildDir "cargo-target\release\$Bin"
    if (-not (Test-Path -LiteralPath $agent) -or -not (Test-Path -LiteralPath (Join-Path $angular 'browser\index.html'))) { Fail 'native or web build is incomplete' }
    if ((& $agent --version) -ne "BaradWatchU $Product $ProductVersion") { Fail 'built version mismatch' }
    $tray = '0'
    if (-not $WithoutTray) {
        $trayVersion = Invoke-Tray (Join-Path $BuildDir "cargo-target\release\$TrayBin") @('--version')
        if ($trayVersion.Text -ne "BaradWatchU Tray $ProductVersion") { Fail 'built tray version mismatch' }
        $tray = '1'
    }
    $marker = @($MarkerHeader, 'product=client', "source=$Root", 'state=complete', "platform=$Platform",
        "version=$ProductVersion", "fingerprint=$before", "tray=$tray", "artifacts=$(Get-ArtifactFingerprint)")
    [IO.File]::WriteAllLines($markerPath, [string[]]$marker)
    Test-Build
}

# --- staging -----------------------------------------------------------------------------

# Installed layout: bin\*.exe and share\baradwatchu-client\{catalog,web}; the agent finds
# its data one level above bin (same layout as the Linux prefix).
function New-Stage([string]$StageDir) {
    if (Test-Path -LiteralPath $StageDir) { Remove-Item -LiteralPath $StageDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'bin') | Out-Null
    Copy-Item -LiteralPath (Join-Path $BuildDir "cargo-target\release\$Bin") -Destination (Join-Path $StageDir 'bin')
    if (-not $WithoutTray) { Copy-Item -LiteralPath (Join-Path $BuildDir "cargo-target\release\$TrayBin") -Destination (Join-Path $StageDir 'bin') }
    $share = Join-Path $StageDir 'share\baradwatchu-client'
    New-Item -ItemType Directory -Force -Path $share | Out-Null
    Copy-Item -LiteralPath (Join-Path $BuildDir 'cargo-target\share\baradwatchu-client\catalog') -Destination $share -Recurse
    Copy-Item -LiteralPath (Join-Path $BuildDir 'angular\browser') -Destination (Join-Path $share 'web') -Recurse
    $problem = Test-RequirementAssets $share
    if ($problem) { Fail "staged check folders are invalid ($problem)" }
}
function Get-StagedFiles([string]$StageDir) {
    $files = @(Get-ChildItem -LiteralPath $StageDir -Recurse -File -Force | ForEach-Object {
            $_.FullName.Substring($StageDir.Length).TrimStart('\').Replace('\', '/')
        })
    [Array]::Sort($files, [StringComparer]::Ordinal)
    return $files
}
function Test-Allowed([string]$Rel) {
    if ($Rel -match '(^|/)\.\.(/|$)' -or $Rel.StartsWith('/') -or $Rel -match '^[A-Za-z]:') { return $false }
    return ($Rel -eq "bin/$Bin" -or $Rel -eq "bin/$TrayBin" -or $Rel.StartsWith('share/baradwatchu-client/'))
}

# --- manifest ----------------------------------------------------------------------------

function Get-ManifestPath { return Join-Path $Prefix 'share\baradwatchu-source\baradwatchu-agent.manifest' }
function Read-InstallManifest {
    $path = Get-ManifestPath
    $lines = [IO.File]::ReadAllLines($path)
    if ($lines.Count -lt 4 -or $lines[0] -ne $ManifestHeader -or $lines[1] -ne $ManifestKind -or -not [string]::Equals($lines[2], $Prefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail 'installation manifest missing, unsafe or mismatched'
    }
    $files = [ordered]@{}
    $shortcuts = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines | Select-Object -Skip 4) {
        if (-not $line) { continue }
        $fields = $line.Split("`t")
        if ($fields.Count -ne 3) { Fail 'invalid manifest entry' }
        if ($fields[0] -eq 'file' -and $fields[1] -match '^[0-9a-f]{64}$' -and (Test-Allowed $fields[2])) { $files[$fields[2]] = $fields[1] }
        elseif ($fields[0] -eq 'shortcut' -and $fields[2] -match '^[A-Za-z0-9 ._-]+\.lnk$') { $shortcuts.Add($fields[2]) }
        else { Fail 'invalid manifest ownership entry' }
    }
    return @{ Version = $lines[3]; Files = $files; Shortcuts = $shortcuts }
}
function Test-HashOk([string]$Path, [string]$Hash) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -eq $Hash
}
# A folder installed by the setup.exe is owned by that setup (like a package manager).
function Assert-NotOwnedBySetup {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($SetupAppId)_is1"
    $entry = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($entry -and $entry.PSObject.Properties['InstallLocation'] -and $entry.InstallLocation) {
        if ([string]::Equals((Get-FullPath $entry.InstallLocation), $Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            Fail "$Prefix is managed by the BaradWatchU setup; uninstall it from Settings > Apps first or choose another -Prefix"
        }
    }
}

# --- running instances -------------------------------------------------------------------

function Get-RunningInstances {
    $targets = @((Join-Path $Prefix "bin\$Bin"), (Join-Path $Prefix "bin\$TrayBin"))
    return @(Get-CimInstance Win32_Process -Filter "Name = '$Bin' OR Name = '$TrayBin'" | Where-Object {
            # Normalize: a process started through an 8.3 short path reports that form.
            $exe = $_.ExecutablePath
            if ($exe) { $exe = Get-FullPath $exe }
            $exe -and ($targets | Where-Object { [string]::Equals($_, $exe, [StringComparison]::OrdinalIgnoreCase) })
        })
}
# Windows has no SIGTERM: ask politely, never TerminateProcess. A short-lived helper posts
# WM_CLOSE to the process's "BaradWatchU Tray" window (the GUI tray quits as from its menu)
# and sends Ctrl+C on the process's own console (agent, dashboard); our console is untouched.
function Send-CloseRequest([int]$ProcessId) {
    $helper = @"
Add-Type -Namespace BaradWatchU -Name Console -MemberDefinition @'
public delegate bool EnumProc(System.IntPtr h, System.IntPtr l);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, System.IntPtr l);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(System.IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(System.IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern bool PostMessage(System.IntPtr h, uint msg, System.IntPtr w, System.IntPtr l);
[DllImport("kernel32.dll")] public static extern bool FreeConsole();
[DllImport("kernel32.dll")] public static extern bool AttachConsole(uint id);
[DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(System.IntPtr handler, bool add);
[DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint ctrlEvent, uint group);
public static void CloseTrayWindow(uint target) {
  EnumWindows((h, l) => {
    uint pid; GetWindowThreadProcessId(h, out pid);
    var title = new System.Text.StringBuilder(64); GetWindowText(h, title, 64);
    if (pid == target && title.ToString() == "BaradWatchU Tray") PostMessage(h, 0x0010, System.IntPtr.Zero, System.IntPtr.Zero);
    return true;
  }, System.IntPtr.Zero);
}
'@
[BaradWatchU.Console]::CloseTrayWindow($ProcessId)
[BaradWatchU.Console]::FreeConsole() | Out-Null
if ([BaradWatchU.Console]::AttachConsole($ProcessId)) {
  [BaradWatchU.Console]::SetConsoleCtrlHandler([System.IntPtr]::Zero, `$true) | Out-Null
  [BaradWatchU.Console]::GenerateConsoleCtrlEvent(0, 0) | Out-Null
  Start-Sleep -Milliseconds 300
  [BaradWatchU.Console]::FreeConsole() | Out-Null
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($helper))
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $powershell -ArgumentList '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded -WindowStyle Hidden -Wait
}
function Stop-RunningInstances {
    $instances = @(Get-RunningInstances)
    if ($instances.Count -eq 0) { return }
    $timeout = 10
    if ($env:BARADWATCHU_STOP_TIMEOUT -match '^\d+$') { $timeout = [int]$env:BARADWATCHU_STOP_TIMEOUT }
    foreach ($instance in $instances) {
        Write-Host "Closing running $($instance.Name) (PID $($instance.ProcessId)) of this installation..."
        if (-not $DryRun) { Send-CloseRequest ([int]$instance.ProcessId) }
    }
    if ($DryRun) { return }
    $deadline = (Get-Date).AddSeconds($timeout)
    do {
        $alive = @($instances | Where-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
        if ($alive.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    $list = ($alive | ForEach-Object { "$($_.Name) PID $($_.ProcessId)" }) -join ', '
    Fail "still running after $timeout s: $list. Close it (Ctrl+C in the dashboard window, Close tray in the tray menu) and retry; nothing was changed"
}
function Show-RunningInstances {
    foreach ($instance in Get-RunningInstances) { Write-Host "  would close $($instance.Name) (PID $($instance.ProcessId))" }
}

# --- Start menu, autostart ---------------------------------------------------------------

function Get-Shortcuts {
    $list = @(@{ Name = 'BaradWatchU Dashboard.lnk'; Target = (Join-Path $Prefix "bin\$Bin"); Arguments = 'dashboard'; Description = 'Apre la dashboard locale di BaradWatchU (chiudi la finestra per fermarla)' })
    if (-not $WithoutTray) {
        $list += @{ Name = 'BaradWatchU Tray.lnk'; Target = (Join-Path $Prefix "bin\$TrayBin"); Arguments = ''; Description = 'Stato di BaradWatchU, notifiche e richieste di consenso' }
    }
    return $list
}
function New-Shortcuts {
    New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    foreach ($entry in Get-Shortcuts) {
        $link = $shell.CreateShortcut((Join-Path $StartMenuDir $entry.Name))
        $link.TargetPath = $entry.Target
        $link.Arguments = $entry.Arguments
        $link.WorkingDirectory = Join-Path $Prefix 'bin'
        $link.Description = $entry.Description
        $link.Save()
    }
}
function Remove-Shortcuts([string[]]$Names) {
    if (-not (Test-Path -LiteralPath $StartMenuDir)) { return }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($name in $Names) {
        $path = Join-Path $StartMenuDir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        # Only shortcuts that still point into this installation are removed.
        $target = $shell.CreateShortcut($path).TargetPath
        if ($target -and (Test-Inside $target $Prefix)) {
            if ($DryRun) { Write-Host "Would remove Start menu entry $path" } else { Remove-Item -LiteralPath $path -Force }
        }
    }
    if (-not $DryRun -and -not (Get-ChildItem -LiteralPath $StartMenuDir -Force)) { Remove-Item -LiteralPath $StartMenuDir -Force }
}
function Remove-TrayAutostart {
    $value = (Get-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue)
    if (-not $value) { return }
    $command = "$($value.$RunValue)".Trim('"')
    try { $command = Get-FullPath $command } catch { return }
    if ([string]::Equals($command, (Join-Path $Prefix "bin\$TrayBin"), [StringComparison]::OrdinalIgnoreCase)) {
        if ($DryRun) { Write-Host 'Would remove the tray autostart entry (HKCU Run)' }
        else { Remove-ItemProperty -Path $RunKey -Name $RunValue; Write-Host 'Removed the tray autostart entry (HKCU Run)' }
    }
}
function Invoke-PostInstall {
    if ($WithoutTray) { return }
    $tray = Join-Path $Prefix "bin\$TrayBin"
    # Start at login: on by default for a first installation; a reinstall keeps the user's
    # choice (tray menu "Avvia al login"); -TrayAutostart forces it, -NoTrayAutostart skips it.
    if ($TrayAutostart -or ($script:FreshInstall -and -not $NoTrayAutostart)) {
        $result = Invoke-Tray $tray @('autostart', 'enable')
        if ($result.Text) { Write-Host $result.Text }
        if ($result.Code -ne 0) { Write-Host 'Warning: tray autostart could not be enabled' -ForegroundColor Yellow }
    } else {
        $result = Invoke-Tray $tray @('autostart', 'status')
        if ($result.Text) { Write-Host "$($result.Text) (unchanged; change it from the tray menu: Avvia al login)" }
    }
    Write-Host "Tray companion: start it with $tray (or the Start menu); closing it does not stop the agent."
}

# --- install / uninstall -----------------------------------------------------------------

function Remove-EmptyFolders([string]$Base) {
    if (-not (Test-Path -LiteralPath $Base -PathType Container)) { return }
    $dirs = @(Get-ChildItem -LiteralPath $Base -Recurse -Directory -Force | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($dir in $dirs) { if (-not (Get-ChildItem -LiteralPath $dir.FullName -Force)) { Remove-Item -LiteralPath $dir.FullName -Force } }
    if (-not (Get-ChildItem -LiteralPath $Base -Force)) { Remove-Item -LiteralPath $Base -Force }
}

function Invoke-Uninstall {
    Assert-NoReparsePoint $Prefix
    Assert-NotOwnedBySetup
    if (-not (Test-Path -LiteralPath (Get-ManifestPath) -PathType Leaf)) { Fail "no installation manifest in $Prefix" }
    $manifest = Read-InstallManifest
    # Preflight every owned path before removing any of them.
    foreach ($rel in $manifest.Files.Keys) {
        $path = Join-Path $Prefix $rel
        if ((Test-Path -LiteralPath $path) -and -not (Test-HashOk $path $manifest.Files[$rel])) { Fail "changed file preserved: $path" }
    }
    Remove-TrayAutostart
    Stop-RunningInstances
    $count = 0
    foreach ($rel in $manifest.Files.Keys) {
        $path = Join-Path $Prefix $rel
        if (Test-Path -LiteralPath $path) {
            if ($DryRun) { Write-Host "Would remove $path" } else { Remove-Item -LiteralPath $path -Force }
            $count++
        }
    }
    Remove-Shortcuts ([string[]]$manifest.Shortcuts)
    if ($DryRun) { Write-Host "Would remove $(Get-ManifestPath)"; Write-Host "Dry-run complete; $count files would be removed."; return }
    Remove-Item -LiteralPath (Get-ManifestPath) -Force
    Remove-EmptyFolders $Prefix
    Write-Host 'Manifest removed; configuration and user data preserved.'
    Write-Host "Uninstall complete; $count files removed."
}

function Invoke-Install {
    if ((Test-Path -LiteralPath $Prefix) -and -not (Test-Path -LiteralPath $Prefix -PathType Container)) { Fail 'prefix exists and is not a directory' }
    Assert-NoReparsePoint $Prefix
    Assert-NotOwnedBySetup
    if ($NoBuild) {
        if (-not (Test-Dependencies 'runtime')) { Fail 'required runtime dependencies are missing; nothing was installed' }
        Test-Build
    } else {
        Invoke-Build
    }
    # First installation = no manifest yet; it decides the start-at-login default.
    $script:FreshInstall = -not (Test-Path -LiteralPath (Get-ManifestPath))
    $stage = Join-Path $BuildDir ('stage-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-Stage $stage
        $staged = @(Get-StagedFiles $stage)
        $old = [ordered]@{}
        $oldShortcuts = @()
        if (Test-Path -LiteralPath (Get-ManifestPath)) {
            $manifest = Read-InstallManifest
            $old = $manifest.Files
            $oldShortcuts = [string[]]$manifest.Shortcuts
        }
        $entries = New-Object System.Collections.Generic.List[string]
        foreach ($rel in $staged) {
            if (-not (Test-Allowed $rel)) { Fail "staged path outside allowed destinations: $rel" }
            $dest = Join-Path $Prefix $rel
            if (Test-Path -LiteralPath $dest) {
                if (-not $old.Contains($rel)) { Fail "unmanaged file exists: $dest" }
                if (-not (Test-HashOk $dest $old[$rel])) { Fail "changed file preserved: $dest" }
            }
            $entries.Add("file`t$((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $stage $rel)).Hash.ToLowerInvariant())`t$rel")
        }
        foreach ($rel in $old.Keys) {
            if ($staged -contains $rel) { continue }
            $dest = Join-Path $Prefix $rel
            if ((Test-Path -LiteralPath $dest) -and -not (Test-HashOk $dest $old[$rel])) { Fail "changed old file preserved: $dest" }
        }
        foreach ($entry in Get-Shortcuts) { $entries.Add("shortcut`t-`t$($entry.Name)") }
        Write-Host "Staged $($staged.Count) files before modifying $Prefix."
        # Last step before any file changes: close this installation's running programs.
        Stop-RunningInstances
        foreach ($rel in $staged) {
            $dest = Join-Path $Prefix $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            $tmp = "$dest.baradwatchu-$([Guid]::NewGuid().ToString('N'))"
            try {
                Copy-Item -LiteralPath (Join-Path $stage $rel) -Destination $tmp
                Move-Item -LiteralPath $tmp -Destination $dest -Force
            } catch {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                Fail "could not replace destination file: $dest ($($_.Exception.Message))"
            }
        }
        foreach ($rel in $old.Keys) {
            if ($staged -contains $rel) { continue }
            $dest = Join-Path $Prefix $rel
            if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
        }
        $manifestPath = Get-ManifestPath
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $manifestPath) | Out-Null
        $content = @($ManifestHeader, $ManifestKind, $Prefix, $ProductVersion) + $entries.ToArray()
        $tmpManifest = "$manifestPath.baradwatchu-$([Guid]::NewGuid().ToString('N'))"
        [IO.File]::WriteAllText($tmpManifest, (($content -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
        Move-Item -LiteralPath $tmpManifest -Destination $manifestPath -Force
        $stale = @($oldShortcuts | Where-Object { (Get-Shortcuts | ForEach-Object { $_.Name }) -notcontains $_ })
        if ($stale.Count -gt 0) { Remove-Shortcuts ([string[]]$stale) }
        New-Shortcuts
        Write-Host "Installed BaradWatchU Client $ProductVersion in $Prefix (Start menu: BaradWatchU). No service or system setting was changed; configuration and user data were preserved."
        Invoke-PostInstall
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-Package {
    if (-not (Test-Dependencies 'package')) { Fail 'required dependencies are missing (see the [REQUIRED] items above); no setup was built' }
    if ($NoBuild) { Test-Build } else { Invoke-Build }
    $iscc = Get-InnoCompiler
    $script = Join-Path $Root 'packaging\windows\baradwatchu-client.iss'
    if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { Fail "Inno Setup script missing: $script" }
    $stage = Join-Path $BuildDir 'package-stage'
    New-Stage $stage
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $tray = if ($WithoutTray) { '0' } else { '1' }
    Invoke-Native 'Inno Setup compiler' { & $iscc /Q "/DAppVersion=$ProductVersion" "/DStageDir=$stage" "/DWithTray=$tray" "/O$OutputDir" $script }
    $setup = Join-Path $OutputDir "BaradWatchU-Client-$ProductVersion-setup.exe"
    if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { Fail "setup not produced: $setup" }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $setup).Hash.ToLowerInvariant()
    Write-Host "Setup built: $setup"
    Write-Host "SHA-256: $hash"
    Write-Host 'The setup is not code-signed: Windows SmartScreen may warn about an unknown publisher.'
}

function Show-Options([string]$Action) {
    Section "BaradWatchU Client $ProductVersion installer for Windows"
    Write-Host ('  {0,-18} {1}' -f 'action', $Action)
    if ($Action -eq 'dependency check') { return }
    if ($Action -ne 'uninstall') { Write-Host ('  {0,-18} {1}' -f 'build cache', $BuildDir) }
    if ($Action -ne 'build-only' -and $Action -ne 'package') { Write-Host ('  {0,-18} {1}' -f 'prefix', $Prefix) }
    if ($Action -eq 'package') { Write-Host ('  {0,-18} {1}' -f 'output', $OutputDir) }
    if ($Action -ne 'uninstall') {
        Write-Host ('  {0,-18} {1}' -f 'tray', $(if ($WithoutTray) { 'not built' } else { 'built and installed' }))
        $autostart = if ($WithoutTray) { 'not applicable' } elseif ($TrayAutostart) { 'enabled after install' } elseif ($NoTrayAutostart) { 'not enabled (a reinstall keeps the current choice)' } else { 'enabled on first install; a reinstall keeps the current choice' }
        Write-Host ('  {0,-18} {1}' -f 'tray autostart', $autostart)
        Write-Host ('  {0,-18} {1}' -f 'reuse build', $(if ($NoBuild) { 'yes (-NoBuild)' } else { 'no' }))
    }
    Write-Host ('  {0,-18} {1}' -f 'dry run', $(if ($DryRun) { 'yes' } else { 'no' }))
}

# --- main --------------------------------------------------------------------------------

if ($Help) { Show-Usage; exit 0 }
if ($Version) { Write-Host "BaradWatchU Client $ProductVersion"; exit 0 }
$installSet = $DryRun -or $NoBuild -or $BuildOnly -or $Uninstall -or $Package -or $Prefix -or $BuildDir -or $OutputDir -or $WithoutTray -or $TrayAutostart -or $NoTrayAutostart
if ($MissingDeps) {
    if ($installSet) { BadArg '-MissingDeps conflicts with other options' }
    Show-Options 'dependency check'
    if (Test-Dependencies 'audit') { exit 0 } else { exit 1 }
}
if ($BuildOnly -and ($DryRun -or $NoBuild -or $Uninstall -or $Prefix -or $Package)) { BadArg '-BuildOnly conflicts with install options' }
if ($BuildOnly -and -not $BuildDir) { BadArg '-BuildOnly requires an explicit -BuildDir DIR' }
if ($WithoutTray -and ($TrayAutostart -or $NoTrayAutostart)) { BadArg 'tray autostart options conflict with -WithoutTray' }
if ($TrayAutostart -and $NoTrayAutostart) { BadArg '-TrayAutostart conflicts with -NoTrayAutostart' }
if ($Uninstall -and ($WithoutTray -or $TrayAutostart -or $NoTrayAutostart)) { BadArg '-Uninstall removes the tray when installed; tray options do not apply' }
if ($Uninstall -and ($NoBuild -or $BuildDir -or $Package)) { BadArg '-Uninstall conflicts with build options' }
if ($Package -and ($Prefix -or $TrayAutostart -or $NoTrayAutostart -or $DryRun)) { BadArg '-Package builds a setup; -Prefix, tray autostart options and -DryRun do not apply' }
if ($OutputDir -and -not $Package) { BadArg '-OutputDir requires -Package' }

if (-not $Prefix) { $Prefix = Join-Path $env:LOCALAPPDATA 'Programs\BaradWatchU' }
if (-not $BuildDir) { $BuildDir = Join-Path $env:LOCALAPPDATA "baradwatchu\build\baradwatchu-agent-$ProductVersion" }
if (-not [IO.Path]::IsPathRooted($Prefix)) { BadArg '-Prefix must be an absolute path' }
if (-not [IO.Path]::IsPathRooted($BuildDir)) { BadArg '-BuildDir must be an absolute path' }
$Prefix = Get-FullPath $Prefix
$BuildDir = Get-FullPath $BuildDir
if ($Prefix.Length -le 3) { BadArg '-Prefix may not be a drive root' }
if (Test-Inside $BuildDir $Root) { BadArg '-BuildDir must be outside the source tree' }
if (Test-Inside $Prefix $Root) { BadArg '-Prefix must be outside the source tree' }
if (-not $OutputDir) { $OutputDir = Join-Path $BuildDir 'dist' }
$OutputDir = Get-FullPath $OutputDir

if ($BuildOnly) {
    Show-Options 'build-only'
    Invoke-Build
    Write-Host "Build-only complete; validated cache at $BuildDir. No installation files changed."
    exit 0
}
if ($Package) { Show-Options 'package'; Invoke-Package; exit 0 }
if ($Uninstall) {
    Show-Options 'uninstall'
    if ($DryRun) { Write-Host 'Dry-run: no files change.'; Show-RunningInstances }
    Invoke-Uninstall
    exit 0
}
if ($DryRun) {
    Show-Options 'install'
    $mode = if ($NoBuild) { 'runtime' } else { 'build' }
    if (-not (Test-Dependencies $mode)) { Write-Host 'A real run would stop here: required dependencies are missing. No changes made.' }
    if ($NoBuild) { Test-Build } else { Write-Host 'Plan: build as the current user, stage artifacts, install manifest-owned files and Start menu entries.' }
    Show-RunningInstances
    Write-Host 'Dry-run complete; no files changed.'
    exit 0
}
Show-Options 'install'
Invoke-Install
exit 0
