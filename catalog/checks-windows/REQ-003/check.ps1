#Requires -Version 5.1
# REQ-003 — Protezione firewall (REQUIREMENTS SEC-014), Windows.
# Effective state of Windows Defender Firewall from the ActiveStore (local + Group Policy
# merged; the default persistent store reports "NotConfigured"), plus third-party firewalls
# registered in Windows Security Center. PASS: every profile enabled with inbound Block, or an
# enabled third-party firewall. FAIL: a profile is off or allows inbound by default.
# WARN: state not readable.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-003'

function Out-Result([string]$Status, [string]$Summary, [string[]]$Details = @()) {
    $json = [ordered]@{ id = $Id; status = $Status; summary = $Summary; details = @($Details) } |
        ConvertTo-Json -Compress
    $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($json)
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
    exit 0
}
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo del firewall' @("$_") }

$details = New-Object System.Collections.Generic.List[string]

$thirdParty = New-Object System.Collections.Generic.List[string]
try {
    foreach ($product in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct)) {
        $on = ((([int]$product.productState) -shr 8) -band 0xF0) -eq 0x10
        $details.Add("Firewall di terze parti $($product.displayName): " + $(if ($on) { 'attivo' } else { 'disattivato' }))
        if ($on) { $thirdParty.Add($product.displayName) }
    }
} catch {
    $details.Add('Centro sicurezza Windows non disponibile per i firewall di terze parti')
}

try {
    $fwProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
} catch {
    if ($thirdParty.Count -gt 0) {
        Out-Result 'PASS' "Firewall di terze parti attivo: $($thirdParty -join ', ')" $details
    }
    $details.Add("Profili di Windows Defender Firewall non leggibili: $($_.Exception.Message)")
    Out-Result 'WARN' 'Non è stato possibile leggere lo stato del firewall' $details
}

$weak = 0
foreach ($fwProfile in $fwProfiles) {
    $enabled = "$($fwProfile.Enabled)" -eq 'True'
    $inbound = "$($fwProfile.DefaultInboundAction)"
    $details.Add("Windows Defender Firewall, profilo $($fwProfile.Name): " +
        $(if ($enabled) { 'attivo' } else { 'DISATTIVATO' }) + ", traffico in ingresso predefinito: $inbound")
    if (-not $enabled -or $inbound -ne 'Block') { $weak++ }
}

if ($fwProfiles.Count -gt 0 -and $weak -eq 0) {
    Out-Result 'PASS' 'Windows Defender Firewall attivo su tutti i profili con blocco del traffico in ingresso' $details
}
if ($thirdParty.Count -gt 0) {
    Out-Result 'PASS' "Firewall di terze parti attivo: $($thirdParty -join ', ')" $details
}
if ($fwProfiles.Count -eq 0) {
    Out-Result 'WARN' 'Nessun profilo firewall leggibile' $details
}
Out-Result 'FAIL' "Windows Defender Firewall non filtra il traffico in ingresso su $weak profili e non c'è un firewall alternativo attivo" $details
