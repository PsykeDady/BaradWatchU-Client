#Requires -Version 5.1
# BaradWatchU Client installer for Windows: the Windows counterpart of install.sh.
# System-wide installation only (Program Files + Windows service), done by the Inno Setup
# setup.exe that this script builds and then runs elevated (UAC). Run it with:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 [options]
param(
    [Alias('h')][switch]$Help,
    [Alias('V')][switch]$Version,
    [switch]$MissingDeps,
    [switch]$DryRun,
    [switch]$NoBuild,
    [switch]$BuildOnly,
    [string]$BuildDir = '',
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
$ServiceName = 'BaradWatchU'
# Inno Setup AppId of the setup.exe (packaging/windows/baradwatchu-client.iss).
$SetupAppId = '{8F3D2B6A-4C1E-4B7A-9E52-6D0B1C7A3E94}'
$SetupKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($SetupAppId)_is1"
$UserSetupKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($SetupAppId)_is1"
# Former per-user installation made by older versions of this script (removed by -Uninstall).
$LegacyPrefix = Join-Path $env:LOCALAPPDATA 'Programs\BaradWatchU'
$LegacyStartMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\BaradWatchU'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValue = 'BaradWatchU-Tray'

function Show-Usage {
    @'
BaradWatchU Client installer for Windows (system-wide, with the Windows service)
Usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 [OPTIONS]
  -Help, -h          Show help          -Version, -V       Show version
  -MissingDeps       Read-only dependency check: [REQUIRED] items block the
                     install, [optional] items only degrade checks
  -DryRun            Print the plan without building or changing anything
  -NoBuild           Reuse a validated source/platform/version build cache
  -BuildOnly         Build and validate the cache; do not install
  -BuildDir DIR      Build cache outside the source tree
                     (default %LOCALAPPDATA%\baradwatchu\build\baradwatchu-agent-VERSION)
  -Uninstall, -U     Run the uninstaller of the system installation; also removes
                     a former per-user installation made by older versions
  -WithoutTray       Do not build/install the baradwatchu-tray companion
  -TrayAutostart     First installation: start the tray at login (default)
  -NoTrayAutostart   First installation: do not start the tray at login. An
                     upgrade keeps the user's choice (tray menu: Avvia al login)
  -Package           Only build the setup.exe (with -OutputDir DIR, default
                     BUILDDIR\dist), e.g. to install it on other machines
Install = build as the current user, build the setup.exe with Inno Setup 6, then
run it elevated (UAC: administrator credentials are required). The setup
installs into Program Files for all users and installs, updates and starts the
BaradWatchU Windows service that keeps the Server connections (tunnels). There
is no per-user installation. Settings, identities, trust stores, custom checks
and history are never touched.
Before the setup runs, the dashboard and tray of the installed version are asked
to close (baradwatchu-agent quit); the setup refuses to replace files while a
program of that folder is still running and never kills it.
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
    if ($Mode -ne 'build') {
        Section '[REQUIRED] setup'
        $iscc = Get-InnoCompiler
        if ($iscc) { DepOk "Inno Setup 6 ($iscc)" } else { DepRequired 'Inno Setup 6 (winget install JRSoftware.InnoSetup)'; $missing++ }
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
        # @(...) around the whole if: PowerShell turns an empty array returned by an `if`
        # expression into $null, and StrictMode then fails on .Count.
        $providers = @(if ($config.PSObject.Properties['providers'] -and $config.providers) { $config.providers.PSObject.Properties })
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
function Test-Allowed([string]$Rel) {
    if ($Rel -match '(^|/)\.\.(/|$)' -or $Rel.StartsWith('/') -or $Rel -match '^[A-Za-z]:') { return $false }
    return ($Rel -eq "bin/$Bin" -or $Rel -eq "bin/$TrayBin" -or $Rel.StartsWith('share/baradwatchu-client/'))
}

# --- system installation (setup.exe) ----------------------------------------------------

function Get-SetupEntry {
    $entry = Get-ItemProperty -Path $SetupKey -ErrorAction SilentlyContinue
    if ($entry -and $entry.PSObject.Properties['InstallLocation'] -and $entry.InstallLocation) { return $entry }
    return $null
}

# Asks the dashboard and tray of the installed version to close (`quit`, same as the button in
# the dashboard and the tray menu). Older agents without `quit` are left to the setup check.
function Close-InstalledPrograms {
    $entry = Get-SetupEntry
    if (-not $entry) { return }
    $agent = Join-Path (Get-FullPath $entry.InstallLocation) "bin\$Bin"
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { return }
    if ($DryRun) { Write-Host "Would ask the dashboard and tray of $agent to close (quit)"; return }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $text = (& $agent quit 2>&1 | Out-String).Trim() } finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -eq 0) {
        if ($text) { Write-Host $text }
        # The tray reads the request at its next poll (every 5 s).
        Start-Sleep -Seconds 6
    } else {
        Write-Host 'The installed version cannot close its dashboard and tray by itself; close them if the setup asks.' -ForegroundColor Yellow
    }
}

function Invoke-Setup([string]$Setup) {
    $arguments = @('/SILENT', '/NORESTART', "/LOG=`"$(Join-Path $BuildDir 'setup.log')`"")
    if (-not $WithoutTray) {
        if ($NoTrayAutostart) { $arguments += '/MERGETASKS="!trayautostart"' }
        elseif ($TrayAutostart) { $arguments += '/MERGETASKS="trayautostart"' }
    }
    Write-Host 'Starting the setup as administrator (UAC prompt)...'
    try {
        $process = Start-Process -FilePath $Setup -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    } catch {
        Fail "the setup was not started (administrator rights refused?): $($_.Exception.Message)"
    }
    if ($process.ExitCode -ne 0) { Fail "the setup ended with exit code $($process.ExitCode); see $(Join-Path $BuildDir 'setup.log')" }
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Host "Installed BaradWatchU Client $ProductVersion for all users; service $ServiceName running."
    } else {
        Fail "files installed, but the $ServiceName service is not running; see $(Join-Path $BuildDir 'setup.log')"
    }
}

function Invoke-Install {
    Assert-NoLegacyInstall
    if ($NoBuild) {
        if (-not (Test-Dependencies 'runtime')) { Fail 'required dependencies are missing; nothing was installed' }
    }
    Invoke-Package | Out-Host
    $setup = Get-SetupPath
    Close-InstalledPrograms
    Invoke-Setup $setup
}

function Invoke-SystemUninstall {
    $entry = Get-SetupEntry
    if (-not $entry) { Write-Host 'No system installation of BaradWatchU Client found.'; return }
    $uninstaller = "$($entry.UninstallString)".Trim('"')
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { Fail "uninstaller missing: $uninstaller" }
    if ($DryRun) { Write-Host "Would run $uninstaller /SILENT as administrator"; return }
    Close-InstalledPrograms
    Write-Host 'Starting the uninstaller as administrator (UAC prompt)...'
    try {
        $process = Start-Process -FilePath $uninstaller -ArgumentList '/SILENT', '/NORESTART' -Verb RunAs -Wait -PassThru
    } catch {
        Fail "the uninstaller was not started (administrator rights refused?): $($_.Exception.Message)"
    }
    if ($process.ExitCode -ne 0) { Fail "the uninstaller ended with exit code $($process.ExitCode)" }
    Write-Host 'System installation removed; configuration and user data preserved.'
}

# --- former per-user installation --------------------------------------------------------
# Older versions of this script installed per user without the service. Both kinds would
# register the same Start menu names and start-at-login value, so install refuses while one
# exists and -Uninstall removes it (manifest-owned, unchanged files only).

function Get-LegacyManifestPath { return Join-Path $LegacyPrefix 'share\baradwatchu-source\baradwatchu-agent.manifest' }

function Assert-NoLegacyInstall {
    if (Test-Path -LiteralPath $UserSetupKey) {
        Fail 'a per-user BaradWatchU setup installation exists: uninstall it from Settings > Apps first'
    }
    if (Test-Path -LiteralPath (Get-LegacyManifestPath) -PathType Leaf) {
        Fail "a per-user installation exists in ${LegacyPrefix}: remove it first with install.ps1 -Uninstall"
    }
}

function Read-LegacyManifest {
    $lines = [IO.File]::ReadAllLines((Get-LegacyManifestPath))
    if ($lines.Count -lt 4 -or $lines[0] -ne $ManifestHeader -or $lines[1] -ne $ManifestKind -or -not [string]::Equals($lines[2], $LegacyPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail 'per-user installation manifest missing, unsafe or mismatched'
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
    return @{ Files = $files; Shortcuts = $shortcuts }
}

function Test-HashOk([string]$Path, [string]$Hash) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -eq $Hash
}

# Running programs of the per-user folder: closed politely, never killed. The per-user agent
# may predate `quit`, so the window close request / Ctrl+C helper is still needed here.
function Get-LegacyInstances {
    $targets = @((Join-Path $LegacyPrefix "bin\$Bin"), (Join-Path $LegacyPrefix "bin\$TrayBin"))
    return @(Get-CimInstance Win32_Process -Filter "Name = '$Bin' OR Name = '$TrayBin'" | Where-Object {
            $exe = $_.ExecutablePath
            if ($exe) { $exe = Get-FullPath $exe }
            $exe -and ($targets | Where-Object { [string]::Equals($_, $exe, [StringComparison]::OrdinalIgnoreCase) })
        })
}
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
function Stop-LegacyInstances {
    $instances = @(Get-LegacyInstances)
    if ($instances.Count -eq 0) { return }
    $timeout = 10
    if ($env:BARADWATCHU_STOP_TIMEOUT -match '^\d+$') { $timeout = [int]$env:BARADWATCHU_STOP_TIMEOUT }
    foreach ($instance in $instances) {
        Write-Host "Closing running $($instance.Name) (PID $($instance.ProcessId)) of the per-user installation..."
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
    Fail "still running after $timeout s: $list. Close it and retry; nothing was changed"
}

function Remove-EmptyFolders([string]$Base) {
    if (-not (Test-Path -LiteralPath $Base -PathType Container)) { return }
    $dirs = @(Get-ChildItem -LiteralPath $Base -Recurse -Directory -Force | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($dir in $dirs) { if (-not (Get-ChildItem -LiteralPath $dir.FullName -Force)) { Remove-Item -LiteralPath $dir.FullName -Force } }
    if (-not (Get-ChildItem -LiteralPath $Base -Force)) { Remove-Item -LiteralPath $Base -Force }
}

function Remove-LegacyInstall {
    if (-not (Test-Path -LiteralPath (Get-LegacyManifestPath) -PathType Leaf)) { return }
    Assert-NoReparsePoint $LegacyPrefix
    Write-Host "Removing the former per-user installation in $LegacyPrefix"
    $manifest = Read-LegacyManifest
    foreach ($rel in $manifest.Files.Keys) {
        $path = Join-Path $LegacyPrefix $rel
        if ((Test-Path -LiteralPath $path) -and -not (Test-HashOk $path $manifest.Files[$rel])) { Fail "changed file preserved: $path" }
    }
    # Start at login: only the value that starts this per-user tray.
    $value = Get-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
    if ($value) {
        $command = "$($value.$RunValue)".Trim('"')
        try { $command = Get-FullPath $command } catch { $command = '' }
        if ([string]::Equals($command, (Join-Path $LegacyPrefix "bin\$TrayBin"), [StringComparison]::OrdinalIgnoreCase)) {
            if ($DryRun) { Write-Host 'Would remove the per-user tray autostart entry (HKCU Run)' }
            else { Remove-ItemProperty -Path $RunKey -Name $RunValue; Write-Host 'Removed the per-user tray autostart entry (HKCU Run)' }
        }
    }
    Stop-LegacyInstances
    $count = 0
    foreach ($rel in $manifest.Files.Keys) {
        $path = Join-Path $LegacyPrefix $rel
        if (Test-Path -LiteralPath $path) {
            if ($DryRun) { Write-Host "Would remove $path" } else { Remove-Item -LiteralPath $path -Force }
            $count++
        }
    }
    if (Test-Path -LiteralPath $LegacyStartMenuDir) {
        $shell = New-Object -ComObject WScript.Shell
        foreach ($name in $manifest.Shortcuts) {
            $path = Join-Path $LegacyStartMenuDir $name
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            $target = $shell.CreateShortcut($path).TargetPath
            if ($target -and (Test-Inside $target $LegacyPrefix)) {
                if ($DryRun) { Write-Host "Would remove Start menu entry $path" } else { Remove-Item -LiteralPath $path -Force }
            }
        }
        if (-not $DryRun -and -not (Get-ChildItem -LiteralPath $LegacyStartMenuDir -Force)) { Remove-Item -LiteralPath $LegacyStartMenuDir -Force }
    }
    if ($DryRun) { Write-Host "Dry-run: $count per-user files would be removed."; return }
    Remove-Item -LiteralPath (Get-LegacyManifestPath) -Force
    Remove-EmptyFolders $LegacyPrefix
    Write-Host "Per-user installation removed ($count files); configuration and user data preserved."
}

function Get-SetupPath { return Join-Path $OutputDir "BaradWatchU-Client-$ProductVersion-setup.exe" }

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
    $setup = Get-SetupPath
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
    if ($Action -eq 'install') { Write-Host ('  {0,-18} {1}' -f 'mode', 'system-wide (Program Files, Windows service), setup run as administrator') }
    if ($Action -ne 'build-only' -and $Action -ne 'uninstall') { Write-Host ('  {0,-18} {1}' -f 'setup output', $OutputDir) }
    if ($Action -ne 'uninstall') {
        Write-Host ('  {0,-18} {1}' -f 'tray', $(if ($WithoutTray) { 'not built' } else { 'built and installed' }))
        $autostart = if ($WithoutTray) { 'not applicable' } elseif ($NoTrayAutostart) { 'not enabled on first install' } else { 'enabled on first install; an upgrade keeps the current choice' }
        Write-Host ('  {0,-18} {1}' -f 'tray autostart', $autostart)
        Write-Host ('  {0,-18} {1}' -f 'reuse build', $(if ($NoBuild) { 'yes (-NoBuild)' } else { 'no' }))
    }
    Write-Host ('  {0,-18} {1}' -f 'dry run', $(if ($DryRun) { 'yes' } else { 'no' }))
}

# --- main --------------------------------------------------------------------------------

# Without [CmdletBinding()] PowerShell puts unknown arguments in $args silently: an option
# that no longer exists (for example -Prefix) must not start a full installation.
if ($args.Count -gt 0) { BadArg "unknown argument: $($args -join ' ')" }
if ($Help) { Show-Usage; exit 0 }
if ($Version) { Write-Host "BaradWatchU Client $ProductVersion"; exit 0 }
$installSet = $DryRun -or $NoBuild -or $BuildOnly -or $Uninstall -or $Package -or $BuildDir -or $OutputDir -or $WithoutTray -or $TrayAutostart -or $NoTrayAutostart
if ($MissingDeps) {
    if ($installSet) { BadArg '-MissingDeps conflicts with other options' }
    Show-Options 'dependency check'
    if (Test-Dependencies 'audit') { exit 0 } else { exit 1 }
}
if ($BuildOnly -and ($DryRun -or $NoBuild -or $Uninstall -or $Package)) { BadArg '-BuildOnly conflicts with install options' }
if ($BuildOnly -and -not $BuildDir) { BadArg '-BuildOnly requires an explicit -BuildDir DIR' }
if ($WithoutTray -and ($TrayAutostart -or $NoTrayAutostart)) { BadArg 'tray autostart options conflict with -WithoutTray' }
if ($TrayAutostart -and $NoTrayAutostart) { BadArg '-TrayAutostart conflicts with -NoTrayAutostart' }
if ($Uninstall -and ($WithoutTray -or $TrayAutostart -or $NoTrayAutostart)) { BadArg '-Uninstall removes the tray when installed; tray options do not apply' }
if ($Uninstall -and ($NoBuild -or $BuildDir -or $Package)) { BadArg '-Uninstall conflicts with build options' }
if ($Package -and ($TrayAutostart -or $NoTrayAutostart -or $DryRun)) { BadArg '-Package only builds the setup; tray autostart options and -DryRun do not apply' }
if ($OutputDir -and $Uninstall) { BadArg '-OutputDir does not apply to -Uninstall' }

if (-not $BuildDir) { $BuildDir = Join-Path $env:LOCALAPPDATA "baradwatchu\build\baradwatchu-agent-$ProductVersion" }
if (-not [IO.Path]::IsPathRooted($BuildDir)) { BadArg '-BuildDir must be an absolute path' }
$BuildDir = Get-FullPath $BuildDir
if (Test-Inside $BuildDir $Root) { BadArg '-BuildDir must be outside the source tree' }
if (-not $OutputDir) { $OutputDir = Join-Path $BuildDir 'dist' }
$OutputDir = Get-FullPath $OutputDir

if ($BuildOnly) {
    Show-Options 'build-only'
    Invoke-Build
    Write-Host "Build-only complete; validated cache at $BuildDir. Nothing was installed."
    exit 0
}
if ($Package) { Show-Options 'package'; Invoke-Package; exit 0 }
if ($Uninstall) {
    Show-Options 'uninstall'
    Remove-LegacyInstall
    Invoke-SystemUninstall
    exit 0
}
if ($DryRun) {
    Show-Options 'install'
    $mode = if ($NoBuild) { 'runtime' } else { 'package' }
    if (-not (Test-Dependencies $mode)) { Write-Host 'A real run would stop here: required dependencies are missing. No changes made.' }
    if ($NoBuild) { Test-Build }
    if ((Test-Path -LiteralPath $UserSetupKey) -or (Test-Path -LiteralPath (Get-LegacyManifestPath) -PathType Leaf)) {
        Write-Host 'A real run would stop here: a per-user installation exists (remove it with install.ps1 -Uninstall).' -ForegroundColor Yellow
    }
    Write-Host 'Plan: build as the current user, build the setup.exe, ask the installed dashboard and tray to close, run the setup as administrator, check the service.'
    Close-InstalledPrograms
    Write-Host 'Dry-run complete; nothing changed.'
    exit 0
}
Show-Options 'install'
Invoke-Install
exit 0
