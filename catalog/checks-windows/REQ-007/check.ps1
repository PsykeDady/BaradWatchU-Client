#Requires -Version 5.1
# REQ-007 — Blocco schermo (REQUIREMENTS SEC-007), Windows.
# The session locks automatically within maxTimeoutMinutes if at least one method holds:
#   A) machine inactivity limit (policy InactivityTimeoutSecs);
#   B) secure screen saver (Group Policy values override the user's own);
#   C) sleep after inactivity with sign-in required on wake (powercfg STANDBYIDLE/CONSOLELOCK,
#      every power source present on the device).
# Grace: Winlogon ScreenSaverGracePeriod, when set, must be <= maxLockGraceSeconds.
# PASS: a method locks in time. FAIL: none does. WARN: settings not readable.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-007'

function Out-Result([string]$Status, [string]$Summary, [string[]]$Details = @()) {
    $json = [ordered]@{ id = $Id; status = $Status; summary = $Summary; details = @($Details) } |
        ConvertTo-Json -Compress
    $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($json)
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
    exit 0
}
function Read-Parameters {
    try {
        $raw = [Console]::In.ReadToEnd()
        if ($raw) { return (ConvertFrom-Json $raw).parameters }
    } catch { }
    return $null
}
function Get-IntParameter($parameters, [string]$Name, [long]$Default) {
    if (-not $parameters -or -not $parameters.PSObject.Properties[$Name]) { return $Default }
    $value = $parameters.$Name
    if (-not ($value -is [int] -or $value -is [long]) -or $value -lt 0) {
        Out-Result 'ERROR' "$Name deve essere un intero non negativo"
    }
    return [long]$value
}
function Get-RegValue([string]$Path, [string]$Name) {
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($item) { return $item.$Name }
    return $null
}
# powercfg /qh prints range lines then the AC and DC indexes; labels are localized, so take
# the last two hexadecimal values. Returns @(ac, dc) in raw units or $null.
function Get-PowerSetting([string]$SubGroup, [string]$Setting) {
    $output = & "$env:SystemRoot\System32\powercfg.exe" /qh SCHEME_CURRENT $SubGroup $Setting 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    $values = @($output | ForEach-Object { if ("$_" -match ':\s*0x([0-9a-fA-F]+)\s*$') { [Convert]::ToInt64($Matches[1], 16) } })
    if ($values.Count -lt 2) { return $null }
    return @($values[$values.Count - 2], $values[$values.Count - 1])
}
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo del blocco schermo' @("$_") }

$parameters = Read-Parameters
$maxSeconds = (Get-IntParameter $parameters 'maxTimeoutMinutes' 5) * 60
$maxGrace = Get-IntParameter $parameters 'maxLockGraceSeconds' 0
$details = New-Object System.Collections.Generic.List[string]
$methods = New-Object System.Collections.Generic.List[string]

# A) Interactive logon: machine inactivity limit.
$inactivity = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
if ($inactivity) {
    $details.Add("Metodo A, limite di inattività del computer: $inactivity s")
    if ([long]$inactivity -gt 0 -and [long]$inactivity -le $maxSeconds) { $methods.Add('limite di inattività') }
} else {
    $details.Add('Metodo A, limite di inattività del computer: non impostato')
}

# B) Screen saver with password; policy values win over user values.
$policy = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
$user = 'HKCU:\Control Panel\Desktop'
function Get-Effective([string]$Name) {
    $value = Get-RegValue $policy $Name
    if ($null -ne $value -and "$value" -ne '') { return "$value" }
    $value = Get-RegValue $user $Name
    if ($null -ne $value) { return "$value" }
    return ''
}
$saverActive = (Get-Effective 'ScreenSaveActive') -eq '1'
$saverSecure = (Get-Effective 'ScreenSaverIsSecure') -eq '1'
$saverExe = Get-Effective 'SCRNSAVE.EXE'
$saverTimeout = 0
[void][long]::TryParse((Get-Effective 'ScreenSaveTimeOut'), [ref]$saverTimeout)
$details.Add("Metodo B, salvaschermo: " + $(if ($saverActive -and $saverExe) { "attivo dopo $saverTimeout s, " + $(if ($saverSecure) { 'con' } else { 'SENZA' }) + ' richiesta di accesso alla ripresa' } else { 'non configurato' }))
if ($saverActive -and $saverExe -and $saverSecure -and $saverTimeout -gt 0 -and $saverTimeout -le $maxSeconds) {
    $methods.Add('salvaschermo protetto')
}

# C) Sleep after inactivity + sign-in on wake, for each power source the device has.
$hasBattery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0
$standby = Get-PowerSetting 'SUB_SLEEP' 'STANDBYIDLE'
$consoleLock = Get-PowerSetting 'SUB_NONE' 'CONSOLELOCK'
if ($null -eq $standby -or $null -eq $consoleLock) {
    $details.Add('Metodo C, sospensione: impostazioni di risparmio energia non leggibili')
} else {
    $sources = if ($hasBattery) { @(0, 1) } else { @(0) }
    $ok = $true
    foreach ($index in $sources) {
        $name = if ($index -eq 0) { 'alimentazione' } else { 'batteria' }
        $seconds = $standby[$index]
        $details.Add("Metodo C, sospensione ($name): " + $(if ($seconds -eq 0) { 'mai' } else { "dopo $seconds s" }) +
            ', accesso alla riattivazione ' + $(if ($consoleLock[$index] -eq 1) { 'richiesto' } else { 'NON richiesto' }))
        if ($seconds -eq 0 -or $seconds -gt $maxSeconds -or $consoleLock[$index] -ne 1) { $ok = $false }
    }
    if ($ok) { $methods.Add('sospensione con accesso alla riattivazione') }
}

$grace = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScreenSaverGracePeriod'
$graceSeconds = $null
if ($null -ne $grace -and "$grace" -match '^\d+$') { $graceSeconds = [long]"$grace" }
$details.Add('Periodo di tolleranza dopo il salvaschermo: ' + $(if ($null -ne $graceSeconds) { "$graceSeconds s (massimo $maxGrace)" } else { 'predefinito di sistema' }))
$details.Add("Soglia richiesta: blocco entro $($maxSeconds / 60) minuti")

if ($methods.Count -eq 0) {
    Out-Result 'FAIL' "La sessione non si blocca automaticamente entro $($maxSeconds / 60) minuti" $details
}
if ($null -ne $graceSeconds -and $graceSeconds -gt $maxGrace -and $methods.Count -eq 1 -and $methods[0] -eq 'salvaschermo protetto') {
    Out-Result 'FAIL' "Il salvaschermo blocca la sessione solo dopo $graceSeconds s di tolleranza (massimo $maxGrace)" $details
}
Out-Result 'PASS' ('Blocco automatico della sessione attivo: ' + ($methods -join ', ')) $details
