#Requires -Version 5.1
# REQ-001 — Aggiornamenti software (REQUIREMENTS SEC-001), Windows.
# Asks the Windows Update Agent (COM, no elevation) for applicable software updates that are
# not installed and not hidden. PASS: none pending. FAIL: updates pending. WARN: the search
# could not complete (offline, service disabled, policy). The search may contact Windows Update.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-001'

function Out-Result([string]$Status, [string]$Summary, [string[]]$Details = @()) {
    $json = [ordered]@{ id = $Id; status = $Status; summary = $Summary; details = @($Details) } |
        ConvertTo-Json -Compress
    $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($json)
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
    exit 0
}
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo degli aggiornamenti' @("$_") }

$details = New-Object System.Collections.Generic.List[string]
try {
    $last = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
    if ($last -and $last.Year -gt 1601) {
        $details.Add('Ultima installazione riuscita: ' + $last.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC')
    }
} catch { }

try {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
} catch {
    $details.Add("Ricerca Windows Update non riuscita: $($_.Exception.Message)")
    Out-Result 'WARN' 'Non è stato possibile interrogare Windows Update' $details
}

$pending = @($result.Updates)
$security = @($pending | Where-Object {
        @($_.Categories | Where-Object { $_.CategoryID -eq '0fa1201d-4330-4fa8-8ae9-b877473b6441' }).Count -gt 0
    }).Count
if ($pending.Count -eq 0) {
    $details.Add('Nessun aggiornamento software in sospeso su Windows Update')
    Out-Result 'PASS' 'Il sistema è aggiornato' $details
}
$details.Add("Aggiornamenti in sospeso: $($pending.Count), di cui di sicurezza: $security")
foreach ($update in ($pending | Select-Object -First 10)) { $details.Add('- ' + $update.Title) }
if ($pending.Count -gt 10) { $details.Add("... e altri $($pending.Count - 10)") }
Out-Result 'FAIL' "Sono disponibili $($pending.Count) aggiornamenti non installati" $details
