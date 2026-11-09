#Requires -Version 5.1
# REQ-005 — VPN aziendale (REQUIREMENTS SEC-011), Windows, Cato Client.
# Operator decision 2026-11-08: the main requirement is that the Cato client is present; its
# shipped CLI (CatoClientCliAT.exe) only answers anti-tamper commands, so `antitamper status`
# proves client + service are there. Connection state = a Cato network adapter Up.
# PASS: present and connected. WARN: present but not connected, or CLI not answering.
# FAIL: Cato client not installed.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-005'

function Out-Result([string]$Status, [string]$Summary, [string[]]$Details = @()) {
    $json = [ordered]@{ id = $Id; status = $Status; summary = $Summary; details = @($Details) } |
        ConvertTo-Json -Compress
    $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($json)
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
    exit 0
}
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo della VPN' @("$_") }

$details = New-Object System.Collections.Generic.List[string]

# Installation: Windows Installer uninstall entries (64- and 32-bit views).
$install = $null
foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    $install = Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'Cato Client' -and
            $_.PSObject.Properties['Publisher'] -and $_.Publisher -like 'Cato Networks*' } |
        Select-Object -First 1
    if ($install) { break }
}
$folder = $null
if ($install -and $install.PSObject.Properties['InstallLocation'] -and $install.InstallLocation) { $folder = $install.InstallLocation }
if (-not $folder) { $folder = Join-Path ${env:ProgramFiles(x86)} 'Cato Networks\Cato Client' }
$cli = Join-Path $folder 'CatoClientCliAT.exe'

if (-not $install -and -not (Test-Path -LiteralPath $cli -PathType Leaf)) {
    Out-Result 'FAIL' 'Il client VPN Cato non è installato' @('Nessuna installazione di "Cato Client" (Cato Networks) trovata')
}
if ($install) { $details.Add("Cato Client $($install.DisplayVersion) installato") }

$signature = Get-AuthenticodeSignature -LiteralPath $cli -ErrorAction SilentlyContinue
if (-not $signature -or $signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '^CN=Cato Networks') {
    $details.Add("CLI Cato assente o con firma non valida: $cli")
    Out-Result 'WARN' 'Il client Cato risulta installato ma la sua CLI non è verificabile' $details
}

# Bounded run of the read-only anti-tamper status query.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $cli
$psi.Arguments = 'antitamper status'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$process = [Diagnostics.Process]::Start($psi)
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$null = $process.StandardError.ReadToEndAsync()
if (-not $process.WaitForExit(20000)) {
    try { $process.Kill() } catch { }
    Out-Result 'WARN' 'Il client Cato non ha risposto entro 20 secondi' $details
}
$text = $stdoutTask.Result
$active = [regex]::Match($text, 'IsActive\s*:\s*(\S+)')
$level = [regex]::Match($text, 'ProtectionLevel\s*:\s*(\S+)')
if ($process.ExitCode -ne 0 -or -not $active.Success) {
    $details.Add("CatoClientCliAT antitamper status: codice $($process.ExitCode)")
    Out-Result 'WARN' 'Il client Cato è installato ma il suo servizio non risponde' $details
}
$details.Add("Anti-manomissione Cato: attiva=$($active.Groups[1].Value), livello=$(if ($level.Success) { $level.Groups[1].Value } else { 'n/d' })")

$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like 'Cato Networks*' })
foreach ($adapter in $adapters) { $details.Add("Scheda $($adapter.InterfaceDescription): $($adapter.Status)") }
if (@($adapters | Where-Object { $_.Status -eq 'Up' }).Count -gt 0) {
    Out-Result 'PASS' 'Client VPN Cato presente e connesso' $details
}
Out-Result 'WARN' 'Client VPN Cato presente ma non connesso' $details
