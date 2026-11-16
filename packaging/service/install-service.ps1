<#
.SYNOPSIS
Installs, updates, stops, starts or removes the BaradWatchU Windows service (Milestone 2).

.DESCRIPTION
Internal component of the all-users setup (packaging/windows/baradwatchu-client.iss), which
runs it elevated during installation, update and uninstall; it can also be run by hand from
an elevated PowerShell.

Registers "BaradWatchU" (LocalSystem, automatic start, restart on failure) running
"baradwatchu-agent.exe service run", then checks that the running service process is
exactly that executable. It never generates keys, starts a Server connection,
never changes firewall rules and never removes registrations or user data.
A Barad Policy applied on this machine with "startOnBoot": false sets a manual start
(the service is still started now); run this again after the policy changes.

The agent must be installed for all users (Program Files): a LocalSystem service must not
run a binary that a user can replace, so per-user copies under %LOCALAPPDATA% are refused.

-Uninstall, -Stop and -Start act only when the installed service runs -Agent.

Each user enables remote requests and starts trusted Server connections from the
Client dashboard. Firewall rules are left to the operator/IT.

STATUS: written for Windows 10/11; not executed on a Windows host yet.
#>
param(
    [string]$Agent = (Join-Path $(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }) 'BaradWatchU\bin\baradwatchu-agent.exe'),
    [switch]$Uninstall,
    [switch]$Stop,
    [switch]$Start,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$Name = 'BaradWatchU'
if (@($Uninstall, $Stop, $Start | Where-Object { $_ }).Count -gt 1) { throw 'Use only one of -Uninstall, -Stop, -Start.' }

function Invoke-Step([string]$Description, [scriptblock]$Action) {
    if ($DryRun) { Write-Host "  would $Description" } else { & $Action }
}

# Executable of the installed service ('' = not installed), from its command line.
function Get-ServiceAgent {
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $service) { return '' }
    if ($service.PathName -match '^"([^"]+)"\s+service\s+run$') { return [IO.Path]::GetFullPath($Matches[1]) }
    return $service.PathName
}

# The service must run exactly $Path (never another or an older executable).
function Confirm-Running([string]$Path) {
    if ($DryRun) { Write-Host "  would check that the running service is $Path"; return }
    for ($i = 0; $i -lt 100; $i++) {
        $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
        if ($service.State -eq 'Running' -and $service.ProcessId) {
            $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
            if ($process -and $process.ExecutablePath) {
                if (-not [string]::Equals([IO.Path]::GetFullPath($process.ExecutablePath), $Path, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "The service runs $($process.ExecutablePath) instead of $Path"
                }
                Start-Sleep -Milliseconds 500
                $again = Get-CimInstance Win32_Service -Filter "Name='$Name'"
                if ($again.State -eq 'Running' -and $again.ProcessId -eq $service.ProcessId) {
                    Write-Host "  running: PID $($service.ProcessId) ($Path)"; return
                }
            }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "The service did not stay running; see Event Viewer > Windows Logs > System (service $Name)"
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $DryRun -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell (Administrator), or use -DryRun to preview.'
}

$full = [IO.Path]::GetFullPath($Agent)
$current = Get-ServiceAgent
if ($Uninstall -or $Stop -or $Start) {
    if (-not $current) { Write-Host 'Service not installed.'; exit 0 }
    if (-not [string]::Equals($current, $full, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "Service left unchanged: it runs $current, not $full."; exit 0
    }
    if ($Stop) {
        Invoke-Step "stop service $Name" { Stop-Service -Name $Name -ErrorAction SilentlyContinue; (Get-Service -Name $Name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
        Write-Host 'Service stopped (still installed).'; exit 0
    }
    if ($Start) {
        Invoke-Step "start service $Name" { Start-Service -Name $Name }
        Confirm-Running $full; exit 0
    }
    Invoke-Step "stop and delete service $Name" {
        Stop-Service -Name $Name -ErrorAction SilentlyContinue
        & sc.exe delete $Name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed ($LASTEXITCODE)" }
    }
    Write-Host 'Service removed. Registrations and request records are kept in %ProgramData%\BaradWatchU\service; user identities are untouched.'
    exit 0
}

if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Agent not found: $full" }
# ProgramW6432: in a 32-bit PowerShell (e.g. started by a 32-bit setup) ProgramFiles points to
# "Program Files (x86)" while the x64 Client lives in the native "Program Files".
$allowed = @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } |
    ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') + '\' }
if (-not ($allowed | Where-Object { $full.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) {
    throw "Refusing $full`: install the Client for all users under Program Files first."
}
if ($full.Contains('"')) { throw "Unsupported characters in $full" }
& $full --version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "$full does not run" }
# `service` without arguments prints its usage on stderr (exit code 2). In Windows PowerShell
# 5.1 a redirected stderr line becomes an error record, which 'Stop' would turn into a
# terminating error before the service is created: probe with 'Continue' locally.
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $usage = (& $full service 2>&1 | Out-String) } finally { $ErrorActionPreference = $previous }
if ($usage -notmatch 'service run') { throw "$full predates the system service: reinstall the Client first" }

# Barad Policy (installed by an administrator, never by this script): only an APPLIED policy
# with "startOnBoot": false changes the start type; otherwise the default automatic start.
$startType = 'Automatic'
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $policy = (& $full policy status --json 2>$null | Out-String) | ConvertFrom-Json -ErrorAction SilentlyContinue
} catch { $policy = $null } finally { $ErrorActionPreference = $previous }
if ($policy -and $policy.state -eq 'APPLIED' -and $policy.startOnBoot -eq $false) { $startType = 'Manual' }

Write-Host 'BaradWatchU Windows service'
Write-Host "  agent:   $full"
if ($current -and -not [string]::Equals($current, $full, [StringComparison]::OrdinalIgnoreCase)) { Write-Host "  replaces: service that ran $current" }
if ($startType -eq 'Automatic') { Write-Host '  account: LocalSystem, automatic start, restart on failure' }
else { Write-Host '  account: LocalSystem, manual start (Barad Policy startOnBoot=false; started now), restart on failure' }
Write-Host '  data:    %ProgramData%\BaradWatchU\service (user connections start only when enabled)'
$binPath = "`"$full`" service run"
$description = 'BaradWatchU: remote audit requests from trusted Servers (consent required).'
# The command line contains quotes (path with spaces). Windows PowerShell 5.1 does not escape
# embedded quotes for native programs, so `sc.exe create/config binPath= ...` received a broken
# command line (error 1639). The service cmdlets and the registry take it as one value.
if ($current) {
    Invoke-Step "update service $Name" {
        Stop-Service -Name $Name -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name ImagePath -Value $binPath
        Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name ObjectName -Value 'LocalSystem'
        Set-Service -Name $Name -StartupType $startType -Description $description
    }
} else {
    Invoke-Step "create service $Name" {
        New-Service -Name $Name -BinaryPathName $binPath -DisplayName 'BaradWatchU Client service' -Description $description -StartupType $startType | Out-Null
    }
}
Invoke-Step 'set restart-on-failure actions' {
    & sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failure failed ($LASTEXITCODE)" }
}
if (-not $DryRun -and (Get-ServiceAgent) -ne $full) { throw "The service command line is not `"$full`" service run" }
# Restart, not just start: a service still running must load the new executable.
# Stop judged by the final state: agents up to 0.0.1 made the SCM report a stop error.
Invoke-Step "(re)start service $Name" {
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    (Get-Service -Name $Name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    Start-Service -Name $Name
}
Confirm-Running $full
Write-Host 'Service ready. Each user enables remote requests and starts trusted Server connections from the Client dashboard (after identity generate).'
