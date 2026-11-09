#Requires -Version 5.1
# REQ-004 — Filtro DNS (REQUIREMENTS SEC-004), Windows.
# Method: HaGeZi blocklist in the system hosts file (operator decision 2026-11-08). The file
# must contain at least one HaGeZi header ("# Title: HaGeZi's", homepage under
# github.com/hagezi/) and at least as many blocking lines as the headers declare
# ("# Number of entries"), with >= minimumHostsEntries blocked names in total.
# PASS: complete HaGeZi list. FAIL: missing, not HaGeZi (when requireHagezi) or truncated.
# WARN: list older than maxListAgeDays or file unreadable. Resolver and browser DoH settings
# are reported as observations only: they do not prove that traffic is filtered.
# Optional -HostsFile: alternative file to inspect (tests); default = the system hosts file.
param([string]$HostsFile = '')
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-004'

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
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo del filtro DNS' @("$_") }

$parameters = Read-Parameters
$minEntries = Get-IntParameter $parameters 'minimumHostsEntries' 10000
$maxAgeDays = Get-IntParameter $parameters 'maxListAgeDays' 30
$requireHagezi = $true
if ($parameters -and $parameters.PSObject.Properties['requireHagezi']) {
    if ($parameters.requireHagezi -isnot [bool]) { Out-Result 'ERROR' 'requireHagezi deve essere true o false' }
    $requireHagezi = $parameters.requireHagezi
}

$details = New-Object System.Collections.Generic.List[string]

# Observations: active resolvers and browser-managed DNS over HTTPS (SEC-005).
try {
    $servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
            Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses } |
            Select-Object -Unique)
    if ($servers.Count -gt 0) { $details.Add('Resolver IPv4 configurati: ' + ($servers -join ', ') + ' (osservazione)') }
} catch { }
foreach ($browser in @(@('Chrome', 'SOFTWARE\Policies\Google\Chrome'), @('Edge', 'SOFTWARE\Policies\Microsoft\Edge'))) {
    $mode = $null
    foreach ($hive in @('HKLM:\', 'HKCU:\')) {
        $value = Get-ItemProperty -Path ($hive + $browser[1]) -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
        if ($value) { $mode = $value.DnsOverHttpsMode; break }
    }
    $details.Add("DNS sicuro di $($browser[0]) (criterio DnsOverHttpsMode): " + $(if ($mode) { $mode } else { 'non impostato: il browser può scavalcare il filtro' }))
}

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
try {
    $configured = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name DataBasePath -ErrorAction Stop).DataBasePath
    if ($configured) { $hostsPath = Join-Path ([Environment]::ExpandEnvironmentVariables($configured)) 'hosts' }
} catch { }
if ($HostsFile) { $hostsPath = $HostsFile }

$blockLines = 0L
$blockedNames = 0L
$declared = 0L
$headers = 0
$oldest = $null
$invariant = [Globalization.CultureInfo]::InvariantCulture
$inHagezi = $false
try {
    foreach ($line in [IO.File]::ReadLines($hostsPath)) {
        $text = $line.Trim()
        if ($text.Length -eq 0) { continue }
        if ($text[0] -eq '#') {
            if ($text.StartsWith("# Title: HaGeZi's")) { $inHagezi = $true; $headers++ }
            elseif ($inHagezi -and $text.StartsWith('# Homepage:') -and $text -notmatch 'github\.com/hagezi/') { $inHagezi = $false; $headers-- }
            elseif ($inHagezi -and $text.StartsWith('# Number of entries:')) {
                $number = 0L
                if ([long]::TryParse($text.Substring(20).Trim(), [ref]$number)) { $declared += $number }
            }
            elseif ($inHagezi -and $text.StartsWith('# Last modified:')) {
                $stamp = [datetime]::MinValue
                $raw = ($text.Substring(16).Trim() -replace '\s*UTC$', '')
                if ([datetime]::TryParseExact($raw, 'dd MMM yyyy HH:mm', $invariant, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$stamp)) {
                    if ($null -eq $oldest -or $stamp -lt $oldest) { $oldest = $stamp }
                }
            }
            continue
        }
        $hash = $text.IndexOf('#')
        if ($hash -ge 0) { $text = $text.Substring(0, $hash).Trim() }
        $fields = $text.Split([char[]]@(' ', "`t"), [StringSplitOptions]::RemoveEmptyEntries)
        if ($fields.Count -lt 2 -or ($fields[0] -ne '0.0.0.0' -and $fields[0] -ne '::')) { continue }
        $names = 0
        for ($i = 1; $i -lt $fields.Count; $i++) {
            $name = $fields[$i].ToLowerInvariant()
            if ($name -ne 'localhost' -and -not $name.EndsWith('.localhost') -and $name -ne 'ip6-localhost' -and $name -ne 'ip6-loopback' -and $name -ne '0.0.0.0') { $names++ }
        }
        if ($names -gt 0) { $blockLines++; $blockedNames += $names }
    }
} catch {
    $details.Add("File hosts non leggibile ($hostsPath): $($_.Exception.Message)")
    Out-Result 'WARN' 'Non è stato possibile leggere il file hosts' $details
}

$details.Add("File hosts: $blockedNames nomi bloccati su $blockLines righe (minimo $minEntries); nomi host omessi")
if ($headers -gt 0) {
    $details.Add("Liste HaGeZi riconosciute: $headers, voci dichiarate: $declared")
    if ($oldest) { $details.Add('Aggiornamento più vecchio: ' + $oldest.ToString('yyyy-MM-dd HH:mm') + " UTC (massimo $maxAgeDays giorni)") }
} else {
    $details.Add('Nessuna intestazione HaGeZi trovata (# Title: HaGeZi''s ..., # Homepage: https://github.com/hagezi/...)')
}

if ($blockedNames -eq 0) {
    Out-Result 'FAIL' 'Il file hosts non contiene una blocklist: nessun filtro DNS rilevato' $details
}
if ($requireHagezi -and $headers -eq 0) {
    Out-Result 'FAIL' 'Il file hosts contiene voci di blocco ma non una lista HaGeZi riconoscibile' $details
}
if ($headers -gt 0 -and $blockLines -lt $declared) {
    Out-Result 'FAIL' "La lista HaGeZi è incompleta: $blockLines righe di blocco su $declared dichiarate" $details
}
if ($blockedNames -lt $minEntries) {
    Out-Result 'FAIL' "Blocklist troppo piccola: $blockedNames nomi bloccati (minimo $minEntries)" $details
}
if ($headers -gt 0 -and $maxAgeDays -gt 0) {
    if ($null -eq $oldest) {
        Out-Result 'WARN' 'Lista HaGeZi presente ma senza data di aggiornamento leggibile' $details
    }
    if (([datetime]::UtcNow - $oldest).TotalDays -gt $maxAgeDays) {
        Out-Result 'WARN' "Lista HaGeZi presente ma non aggiornata da più di $maxAgeDays giorni" $details
    }
}
Out-Result 'PASS' $(if ($headers -gt 0) { 'Filtro DNS attivo: lista HaGeZi completa nel file hosts' } else { 'Filtro DNS attivo: blocklist completa nel file hosts' }) $details
