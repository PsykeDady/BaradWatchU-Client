#Requires -Version 5.1
# REQ-002 provider "bitdefender-gravityzone": Bitdefender Endpoint Security Tools (BEST) for
# Windows, managed by GravityZone. UNVERIFIED on a real endpoint: written from Bitdefender's public
# docs (install folder "Bitdefender\Endpoint Security", product.console.exe /c GetUpdateStatus
# antivirus) plus Windows Security Center. Service names are not documented: services whose
# display name contains "Bitdefender" are inspected. Unobservable facts are WARN, never PASS.
#   FAIL: not installed; a Bitdefender automatic service stopped; Security Center reports it off;
#         signature update older than maxSignatureAgeDays (when the date is readable).
#   WARN: not registered in Security Center, signatures not fresh, company not verifiable.
# Parameters: maxSignatureAgeDays (default 3), expectedCompanyId (default "": not checked),
# installDir (default "%ProgramFiles%\Bitdefender\Endpoint Security").
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
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo di Bitdefender GravityZone' @("$_") }

$parameters = Read-Parameters
$maxAge = Read-MaxAge $parameters 3
$installDir = Join-Path $env:ProgramFiles 'Bitdefender\Endpoint Security'
$company = ''
if ($parameters -and $parameters.PSObject.Properties['installDir']) { $installDir = "$($parameters.installDir)" }
if ($parameters -and $parameters.PSObject.Properties['expectedCompanyId']) { $company = "$($parameters.expectedCompanyId)" }
$note = 'Provider basato sulla documentazione pubblica Bitdefender: da validare su un endpoint reale'
$details = New-Object System.Collections.Generic.List[string]
$problems = New-Object System.Collections.Generic.List[string]
$unknown = New-Object System.Collections.Generic.List[string]

$console = Join-Path $installDir 'product.console.exe'
$uninstall = @()
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    try {
        $uninstall += @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'Bitdefender Endpoint Security Tools*' })
    } catch { }
}
if (-not (Test-Path -LiteralPath $console -PathType Leaf) -and $uninstall.Count -eq 0) {
    Out-Result 'FAIL' 'Bitdefender GravityZone non risulta installato' @("$console assente e nessuna voce di disinstallazione Bitdefender Endpoint Security Tools", $note)
}
foreach ($entry in $uninstall) { $details.Add("installato: $($entry.DisplayName) $($entry.DisplayVersion)") }

$services = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Bitdefender*' })
if ($services.Count -eq 0) {
    $unknown.Add('nessun servizio Bitdefender individuato')
} else {
    foreach ($service in $services) {
        $start = "$($service.StartType)"
        $details.Add("servizio $($service.Name): $($service.Status), avvio $start")
        if ($start -eq 'Automatic' -and "$($service.Status)" -ne 'Running') { $problems.Add("servizio $($service.Name) non in esecuzione") }
    }
}

$products = Get-WscProducts
if ($null -eq $products) {
    $unknown.Add('Centro sicurezza Windows non disponibile')
} else {
    $bitdefender = @($products | Where-Object { "$($_.displayName)" -like '*Bitdefender*' })
    if ($bitdefender.Count -eq 0) { $unknown.Add('Bitdefender non registrato nel Centro sicurezza Windows') }
    foreach ($product in $bitdefender) {
        $active = Test-WscOn $product
        $fresh = Test-WscFresh $product
        $details.Add("Centro sicurezza: $($product.displayName) " + $(if ($active) { 'attivo' } else { 'DISATTIVATO' }) + ', firme ' + $(if ($fresh) { 'aggiornate' } else { 'non aggiornate' }))
        if (-not $active) { $problems.Add('protezione in tempo reale disattivata secondo il Centro sicurezza') }
        elseif (-not $fresh) { $unknown.Add('firme non aggiornate secondo il Centro sicurezza') }
    }
}

if (Test-Path -LiteralPath $console -PathType Leaf) {
    try {
        $text = (& $console /c GetUpdateStatus antivirus 2>&1 | Out-String).Trim()
        if ($text) { $details.Add("GetUpdateStatus antivirus: $($text -replace '\s+', ' ')") }
        $when = $null
        foreach ($line in ($text -split "`r?`n")) {
            $candidate = ($line -split ':', 2)[-1].Trim()
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse($candidate, [ref]$parsed)) { $when = $parsed; break }
        }
        if ($null -ne $when) {
            $age = [int][math]::Floor(((Get-Date) - $when).TotalDays)
            $details.Add("ultimo aggiornamento firme: $($when.ToString('s')) ($age giorni; massimo $maxAge)")
            if ($age -gt $maxAge) { $problems.Add("firme non aggiornate da $age giorni (massimo $maxAge)") }
        } else {
            $details.Add('data dell''ultimo aggiornamento non riconosciuta nell''output di product.console')
        }
    } catch {
        $unknown.Add("product.console.exe non eseguibile: $($_.Exception.Message)")
    }
} else {
    $unknown.Add("product.console.exe non trovato in $installDir")
}

if ($company) { $unknown.Add("appartenenza all'azienda GravityZone $company non verificabile") }

if ($problems.Count -gt 0) {
    foreach ($item in $unknown) { $details.Add("non verificato: $item") }
    $details.Add($note)
    Out-Result 'FAIL' ('Bitdefender GravityZone non conforme: ' + ($problems -join '; ')) $details
}
$details.Add($note)
if ($unknown.Count -gt 0) {
    Out-Result 'WARN' ('Bitdefender GravityZone installato ma non verificabile: ' + ($unknown -join '; ')) $details
}
Out-Result 'PASS' 'Bitdefender GravityZone attivo con firme aggiornate' $details
