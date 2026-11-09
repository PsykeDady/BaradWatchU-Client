#Requires -Version 5.1
# REQ-009 — Sicurezza di avvio (REQUIREMENTS SEC-012/013), Windows.
# Unprivileged sources: GetFirmwareType (UEFI vs legacy BIOS), the Secure Boot state Windows
# records at boot (HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State), TPM version from
# the TPM Base Services (Tbsi_GetDeviceInfo; Get-Tpm/Win32_Tpm need administrator rights).
# PASS: UEFI with Secure Boot on and TPM 2.0. FAIL: Secure Boot off, legacy BIOS, no TPM 2.0.
# WARN: state undeterminable. Local evidence alone does not prove full boot integrity.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-009'

function Out-Result([string]$Status, [string]$Summary, [string[]]$Details = @()) {
    $json = [ordered]@{ id = $Id; status = $Status; summary = $Summary; details = @($Details) } |
        ConvertTo-Json -Compress
    $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($json)
    $out = [Console]::OpenStandardOutput()
    $out.Write($bytes, 0, $bytes.Length)
    $out.Flush()
    exit 0
}
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo della sicurezza di avvio' @("$_") }

$source = @'
using System; using System.Runtime.InteropServices;
public static class BaradBoot {
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFirmwareType(out int type);
  [StructLayout(LayoutKind.Sequential)] struct TpmDeviceInfo { public uint StructVersion; public uint TpmVersion; public uint TpmInterfaceType; public uint TpmImpRevision; }
  [DllImport("tbs.dll")] static extern uint Tbsi_GetDeviceInfo(uint size, ref TpmDeviceInfo info);
  // 1 = BIOS, 2 = UEFI, 0 = unknown.
  public static int FirmwareType() { int type; return GetFirmwareType(out type) ? type : 0; }
  // 1 = TPM 1.2, 2 = TPM 2.0, 0 = no TPM (TBS_E_TPM_NOT_FOUND), -1 = error.
  public static int TpmVersion() {
    TpmDeviceInfo info = new TpmDeviceInfo(); info.StructVersion = 1;
    uint result = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf(typeof(TpmDeviceInfo)), ref info);
    if (result == 0) return (int)info.TpmVersion;
    if (result == 0x8028400F) return 0;
    return -1;
  }
}
'@

$details = New-Object System.Collections.Generic.List[string]
$firmware = 0
$tpm = -1
try {
    Add-Type -TypeDefinition $source -Language CSharp
    $firmware = [BaradBoot]::FirmwareType()
    $tpm = [BaradBoot]::TpmVersion()
} catch {
    $details.Add("API di sistema non disponibili: $($_.Exception.Message)")
}
if ($tpm -lt 0) {
    # Fallback: Plug and Play security devices (no elevation).
    $device = @(Get-PnpDevice -Class SecurityDevices -PresentOnly -ErrorAction SilentlyContinue |
            Where-Object { $_.FriendlyName -match 'Trusted Platform Module' -and $_.Status -eq 'OK' })
    if ($device.Count -gt 0) {
        $tpm = if ($device[0].FriendlyName -match '2\.0') { 2 } else { 1 }
        $details.Add("TPM rilevato tramite Plug and Play: $($device[0].FriendlyName)")
    }
}

$secureBoot = $null
$state = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
if ($state) { $secureBoot = [int]$state.UEFISecureBootEnabled -eq 1 }

$details.Add('Firmware: ' + $(switch ($firmware) { 1 { 'BIOS legacy' } 2 { 'UEFI' } default { 'non determinabile' } }))
$details.Add('Secure Boot: ' + $(if ($null -eq $secureBoot) { 'stato non registrato' } elseif ($secureBoot) { 'attivo' } else { 'disattivato' }))
$details.Add('TPM: ' + $(switch ($tpm) { 2 { 'versione 2.0' } 1 { 'versione 1.2' } 0 { 'assente o disabilitato' } default { 'non determinabile' } }))

$problems = New-Object System.Collections.Generic.List[string]
if ($firmware -eq 1) { $problems.Add('avvio in modalità BIOS legacy: Secure Boot non disponibile') }
elseif ($secureBoot -eq $false) { $problems.Add('Secure Boot disattivato') }
if ($tpm -eq 0) { $problems.Add('TPM assente') }
elseif ($tpm -eq 1) { $problems.Add('TPM 1.2 invece di 2.0') }
if ($problems.Count -gt 0) {
    Out-Result 'FAIL' ('Protezioni di avvio insufficienti: ' + ($problems -join '; ')) $details
}
if ($null -eq $secureBoot -or $tpm -lt 0 -or $firmware -eq 0) {
    Out-Result 'WARN' 'Non è stato possibile verificare completamente Secure Boot e TPM' $details
}
Out-Result 'PASS' 'Avvio UEFI con Secure Boot attivo e TPM 2.0 presente' $details
