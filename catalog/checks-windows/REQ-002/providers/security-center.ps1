#Requires -Version 5.1
# REQ-002 provider "security-center": any antivirus registered in Windows Security Center
# (root/SecurityCenter2, workstation SKUs; no elevation). Keeps the pre-provider behaviour for
# third-party products. PASS: a registered antivirus is on with fresh signatures. FAIL: none
# registered or all off. WARN: on but signatures not up to date, or Security Center unavailable.
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
trap { Out-Result 'ERROR' 'Errore inatteso durante la lettura del Centro sicurezza Windows' @("$_") }

$products = Get-WscProducts
if ($null -eq $products) {
    Out-Result 'WARN' 'Centro sicurezza Windows non disponibile (es. edizione Server)'
}
$details = New-Object System.Collections.Generic.List[string]
$on = New-Object System.Collections.Generic.List[string]
$stale = 0
foreach ($product in $products) {
    $active = Test-WscOn $product
    $fresh = Test-WscFresh $product
    $details.Add("$($product.displayName): " + $(if ($active) { 'attivo' } else { 'disattivato' }) +
        ', firme ' + $(if ($fresh) { 'aggiornate' } else { 'non aggiornate' }))
    if ($active) { $on.Add($product.displayName); if (-not $fresh) { $stale++ } }
}
if ($products.Count -eq 0) { Out-Result 'FAIL' 'Nessun antivirus registrato nel Centro sicurezza Windows' }
if ($on.Count -eq 0) { Out-Result 'FAIL' 'Gli antivirus registrati nel Centro sicurezza sono tutti disattivati' $details }
if ($stale -gt 0) { Out-Result 'WARN' 'Antivirus attivo ma con firme non aggiornate secondo il Centro sicurezza' $details }
Out-Result 'PASS' "Antivirus attivo secondo il Centro sicurezza: $($on -join ', ')" $details
