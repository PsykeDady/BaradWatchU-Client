#Requires -Version 5.1
# REQ-006 — Cifratura dei dati (REQUIREMENTS SEC-006), Windows, BitLocker.
# Unprivileged source: the Shell property System.Volume.BitLockerProtection that Explorer shows
# (BitLocker WMI, manage-bde and Get-BitLockerVolume require administrator rights).
# Values: 1 on, 2 off, 3 encrypting, 4 decrypting, 5 suspended, 6 on and locked; other or empty
# = unknown or not encryptable. PASS: system drive protected (and every other fixed drive).
# FAIL: system drive not protected. WARN: in progress, other fixed drives unprotected, unknown.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-006'

function Out-Result([string]$Status, [string]$Summary, [string[]]$Details = @()) {
    $json = [ordered]@{ id = $Id; status = $Status; summary = $Summary; details = @($Details) } |
        ConvertTo-Json -Compress
    $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($json)
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
    exit 0
}
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo della cifratura' @("$_") }

$labels = @{ 1 = 'attiva'; 2 = 'disattivata'; 3 = 'cifratura in corso'; 4 = 'decifratura in corso'; 5 = 'sospesa'; 6 = 'attiva (unità bloccata)' }
$details = New-Object System.Collections.Generic.List[string]
$systemDrive = "$env:SystemDrive".ToUpperInvariant()
$shell = New-Object -ComObject Shell.Application
$systemState = $null
$otherWeak = 0
$otherUnknown = 0
foreach ($disk in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
    $drive = "$($disk.DeviceID)".ToUpperInvariant()
    $value = $null
    try { $value = $shell.NameSpace($drive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch { }
    $state = 0
    if ($null -ne $value -and "$value" -match '^\d+$') { $state = [int]"$value" }
    $label = if ($labels.ContainsKey($state)) { $labels[$state] } else { 'non determinabile o non cifrabile' }
    $details.Add("Unità $drive" + $(if ($drive -eq $systemDrive) { ' (sistema)' } else { '' }) + ": BitLocker $label")
    if ($drive -eq $systemDrive) { $systemState = $state }
    elseif ($state -eq 1 -or $state -eq 6) { }
    elseif ($labels.ContainsKey($state)) { $otherWeak++ }
    else { $otherUnknown++ }
}
$details.Add('Stato letto senza privilegi dalla proprietà di Esplora file; dettagli su protezioni e metodo richiedono un amministratore')

if ($null -eq $systemState) {
    Out-Result 'WARN' "Unità di sistema $systemDrive non trovata tra i dischi fissi" $details
}
switch ($systemState) {
    { $_ -in 2, 4 } { Out-Result 'FAIL' "L'unità di sistema non è cifrata con BitLocker" $details }
    5 { Out-Result 'FAIL' "BitLocker è sospeso sull'unità di sistema: i dati non sono protetti" $details }
    3 { Out-Result 'WARN' "Cifratura BitLocker dell'unità di sistema in corso" $details }
    0 { Out-Result 'WARN' "Non è stato possibile determinare lo stato di BitLocker sull'unità di sistema" $details }
}
if ($otherWeak -gt 0) {
    Out-Result 'WARN' "Unità di sistema cifrata, ma $otherWeak altre unità fisse non sono protette" $details
}
if ($otherUnknown -gt 0) {
    Out-Result 'WARN' "Unità di sistema cifrata; lo stato di $otherUnknown altre unità fisse non è determinabile" $details
}
Out-Result 'PASS' "Unità di sistema cifrata con BitLocker" $details
