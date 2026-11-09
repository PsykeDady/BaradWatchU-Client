#Requires -Version 5.1
# REQ-002 — Protezione antivirus (REQUIREMENTS SEC-003), Windows.
# Sources (no elevation): Windows Security Center (root/SecurityCenter2, workstation SKUs) and,
# for Microsoft Defender, Get-MpComputerStatus. PASS: an antivirus is enabled with recent
# signatures. FAIL: none registered, or every registered product is off / real-time protection
# is off. WARN: signatures older than maxSignatureAgeDays or state undeterminable.
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
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo antivirus' @("$_") }

$parameters = Read-Parameters
$maxAge = 7
if ($parameters -and $parameters.PSObject.Properties['maxSignatureAgeDays']) {
    $maxAge = $parameters.maxSignatureAgeDays
    if (-not ($maxAge -is [int] -or $maxAge -is [long]) -or $maxAge -lt 0) {
        Out-Result 'ERROR' 'maxSignatureAgeDays deve essere un intero non negativo'
    }
}

$details = New-Object System.Collections.Generic.List[string]
$products = $null
try {
    $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct)
} catch {
    $details.Add('Centro sicurezza Windows non disponibile (es. edizione Server)')
}

# productState: byte 2 = engine state (0x10/0x11 on), byte 3 = signatures (0x00 up to date).
$enabled = New-Object System.Collections.Generic.List[string]
$disabled = 0
$outdated = 0
if ($null -ne $products) {
    foreach ($product in $products) {
        $state = [int]$product.productState
        $on = (($state -shr 8) -band 0xF0) -eq 0x10
        $fresh = ($state -band 0xFF) -eq 0x00
        $label = "$($product.displayName): " + $(if ($on) { 'attivo' } else { 'disattivato' }) +
            ', firme ' + $(if ($fresh) { 'aggiornate' } else { 'non aggiornate' }) + ' secondo il Centro sicurezza'
        $details.Add($label)
        if ($on) { $enabled.Add($product.displayName); if (-not $fresh) { $outdated++ } } else { $disabled++ }
    }
}

# Microsoft Defender: authoritative real-time and signature-age data when it is the active engine.
$defenderActive = $false
$defenderStale = $false
$defenderOff = $false
try {
    $mp = Get-MpComputerStatus
    if ($mp.AMRunningMode -in @('Normal', 'EDR Block Mode')) {
        $defenderActive = $true
        $details.Add("Microsoft Defender: protezione in tempo reale $(if ($mp.RealTimeProtectionEnabled) { 'attiva' } else { 'DISATTIVATA' }), età firme $($mp.AntivirusSignatureAge) giorni (massimo $maxAge), protezione anti-manomissione $(if ($mp.IsTamperProtected) { 'attiva' } else { 'non attiva' })")
        if (-not $mp.RealTimeProtectionEnabled -or -not $mp.AntivirusEnabled) { $defenderOff = $true }
        if ($mp.AntivirusSignatureAge -gt $maxAge) { $defenderStale = $true }
    } else {
        $details.Add("Microsoft Defender in modalità $($mp.AMRunningMode)")
    }
} catch {
    $details.Add('Stato di Microsoft Defender non leggibile')
}

$thirdParty = @($enabled | Where-Object { $_ -notmatch 'Defender' })
if ($thirdParty.Count -gt 0) {
    if ($outdated -gt 0) { Out-Result 'WARN' 'Antivirus attivo ma con firme non aggiornate' $details }
    Out-Result 'PASS' "Protezione antivirus attiva: $($thirdParty -join ', ')" $details
}
if ($defenderActive) {
    if ($defenderOff) { Out-Result 'FAIL' 'Microsoft Defender è presente ma la protezione in tempo reale è disattivata' $details }
    if ($defenderStale) { Out-Result 'WARN' "Microsoft Defender è attivo ma le firme hanno più di $maxAge giorni" $details }
    Out-Result 'PASS' 'Microsoft Defender attivo con firme aggiornate' $details
}
if ($enabled.Count -gt 0) {
    Out-Result 'WARN' 'Il Centro sicurezza segnala un antivirus attivo ma il suo stato non è verificabile' $details
}
if ($null -ne $products -and $products.Count -gt 0) {
    Out-Result 'FAIL' 'Gli antivirus registrati sono tutti disattivati' $details
}
if ($null -ne $products) {
    Out-Result 'FAIL' 'Nessun antivirus registrato nel Centro sicurezza Windows' $details
}
Out-Result 'WARN' 'Non è stato possibile determinare lo stato della protezione antivirus' $details
