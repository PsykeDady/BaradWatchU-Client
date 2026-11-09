#Requires -Version 5.1
# REQ-002 provider "defender": Microsoft Defender Antivirus (Get-MpComputerStatus, no elevation).
# PASS: Defender is the active engine (AMRunningMode Normal / EDR Block Mode) with real-time
# protection on and signatures not older than maxSignatureAgeDays. FAIL: passive/disabled, or
# real-time protection off. WARN: signatures too old, or state unreadable.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-002'

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
function Read-MaxAge($Parameters, [int]$Default) {
    $value = $Default
    if ($Parameters -and $Parameters.PSObject.Properties['maxSignatureAgeDays']) {
        $value = $Parameters.maxSignatureAgeDays
        if (-not ($value -is [int] -or $value -is [long]) -or $value -lt 0) {
            Out-Result 'ERROR' 'maxSignatureAgeDays deve essere un intero non negativo'
        }
    }
    return $value
}
# Windows Security Center productState: byte 2 = engine (0x10/0x11 on), byte 3 = signatures (0x00 fresh).
function Get-WscProducts {
    try { return ,@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct) } catch { return $null }
}
function Test-WscOn($Product) { return (((([int]$Product.productState) -shr 8) -band 0xF0) -eq 0x10) }
function Test-WscFresh($Product) { return ((([int]$Product.productState) -band 0xFF) -eq 0x00) }
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo di Microsoft Defender' @("$_") }

$maxAge = Read-MaxAge (Read-Parameters) 7
$details = New-Object System.Collections.Generic.List[string]
try {
    $mp = Get-MpComputerStatus
} catch {
    Out-Result 'WARN' 'Stato di Microsoft Defender non leggibile' @("Get-MpComputerStatus: $($_.Exception.Message)")
}
$details.Add("modalità: $($mp.AMRunningMode)")
$details.Add("protezione in tempo reale: $(if ($mp.RealTimeProtectionEnabled) { 'attiva' } else { 'DISATTIVATA' })")
$details.Add("età firme: $($mp.AntivirusSignatureAge) giorni (massimo $maxAge)")
$details.Add("protezione anti-manomissione: $(if ($mp.IsTamperProtected) { 'attiva' } else { 'non attiva' })")
if ($mp.AMRunningMode -notin @('Normal', 'EDR Block Mode')) {
    Out-Result 'FAIL' "Microsoft Defender non è l'antivirus attivo (modalità $($mp.AMRunningMode))" $details
}
if (-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) {
    Out-Result 'FAIL' 'Microsoft Defender è presente ma la protezione in tempo reale è disattivata' $details
}
if ($mp.AntivirusSignatureAge -gt $maxAge) {
    Out-Result 'WARN' "Microsoft Defender è attivo ma le firme hanno più di $maxAge giorni" $details
}
Out-Result 'PASS' 'Microsoft Defender attivo con firme aggiornate' $details
