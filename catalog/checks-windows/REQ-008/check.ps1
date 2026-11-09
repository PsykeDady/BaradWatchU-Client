#Requires -Version 5.1
# REQ-008 — Sicurezza delle password (REQUIREMENTS SEC-008/009/010), Windows local accounts.
# Unprivileged sources: SAM domain password policy (samlib SamQueryInformationDomain with
# DOMAIN_READ_PASSWORD_PARAMETERS: max age, min length, complexity — the data `secedit` needs
# elevation for), Winlogon PasswordExpiryWarning (default 5 days), local accounts.
# FAIL: max age 0/never or > maxPasswordAgeDays, min length < minimumLength, complexity off
# while required, warning < minimumWarningDays, or an enabled local account whose password
# never expires (operator decision 2026-11-08). WARN: policy not readable, or accounts governed
# elsewhere (domain, Microsoft account). Account names are never reported (ordinals only).
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Id = 'REQ-008'

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
trap { Out-Result 'ERROR' 'Errore inatteso durante il controllo delle password' @("$_") }

$parameters = Read-Parameters
$maxAge = Get-IntParameter $parameters 'maxPasswordAgeDays' 60
$minWarning = Get-IntParameter $parameters 'minimumWarningDays' 10
$minLength = Get-IntParameter $parameters 'minimumLength' 14
$requireComplexity = $true
if ($parameters -and $parameters.PSObject.Properties['requireComplexity']) {
    if ($parameters.requireComplexity -isnot [bool]) { Out-Result 'ERROR' 'requireComplexity deve essere true o false' }
    $requireComplexity = $parameters.requireComplexity
}

$details = New-Object System.Collections.Generic.List[string]
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

$source = @'
using System; using System.Runtime.InteropServices;
public static class BaradSam {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct UnicodeString { public ushort Length; public ushort MaximumLength; public string Buffer; }
  [StructLayout(LayoutKind.Sequential)]
  struct ObjectAttributes { public int Length; public IntPtr Root; public IntPtr Name; public uint Attributes; public IntPtr Security; public IntPtr Qos; }
  [DllImport("samlib.dll")] static extern int SamConnect(IntPtr server, out IntPtr handle, uint access, ref ObjectAttributes attributes);
  [DllImport("samlib.dll", CharSet = CharSet.Unicode)] static extern int SamLookupDomainInSamServer(IntPtr server, ref UnicodeString name, out IntPtr sid);
  [DllImport("samlib.dll")] static extern int SamOpenDomain(IntPtr server, uint access, IntPtr sid, out IntPtr domain);
  [DllImport("samlib.dll")] static extern int SamQueryInformationDomain(IntPtr domain, int infoClass, out IntPtr buffer);
  [DllImport("samlib.dll")] static extern int SamFreeMemory(IntPtr buffer);
  [DllImport("samlib.dll")] static extern int SamCloseHandle(IntPtr handle);
  // Returns { minLength, properties, maxAgeDays (-1 = never) } or throws with the NTSTATUS.
  public static long[] PasswordPolicy(string domainName) {
    ObjectAttributes attributes = new ObjectAttributes();
    attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
    IntPtr server, domain, sid, buffer;
    int status = SamConnect(IntPtr.Zero, out server, 0x21, ref attributes);
    if (status != 0) throw new Exception("SamConnect 0x" + status.ToString("X8"));
    try {
      UnicodeString name = new UnicodeString();
      name.Buffer = domainName; name.Length = (ushort)(domainName.Length * 2); name.MaximumLength = (ushort)(name.Length + 2);
      status = SamLookupDomainInSamServer(server, ref name, out sid);
      if (status != 0) throw new Exception("SamLookupDomainInSamServer 0x" + status.ToString("X8"));
      try {
        status = SamOpenDomain(server, 0x1, sid, out domain);
        if (status != 0) throw new Exception("SamOpenDomain 0x" + status.ToString("X8"));
        try {
          status = SamQueryInformationDomain(domain, 1, out buffer);
          if (status != 0) throw new Exception("SamQueryInformationDomain 0x" + status.ToString("X8"));
          long minLength = (ushort)Marshal.ReadInt16(buffer, 0);
          long properties = (uint)Marshal.ReadInt32(buffer, 4);
          long maxAge = Marshal.ReadInt64(buffer, 8);
          SamFreeMemory(buffer);
          long days = (maxAge == long.MinValue || maxAge == 0) ? -1 : (-maxAge) / 864000000000L;
          return new long[] { minLength, properties, days };
        } finally { SamCloseHandle(domain); }
      } finally { SamFreeMemory(sid); }
    } finally { SamCloseHandle(server); }
  }
}
'@

$policy = $null
try {
    Add-Type -TypeDefinition $source -Language CSharp
    $policy = [BaradSam]::PasswordPolicy($env:COMPUTERNAME)
} catch {
    $details.Add("Criterio password locale non leggibile tramite SAM: $($_.Exception.Message)")
}

if ($null -ne $policy) {
    $policyMinLength = $policy[0]
    $complex = ($policy[1] -band 1) -eq 1
    $policyMaxAge = $policy[2]
    $details.Add('Durata massima della password: ' + $(if ($policyMaxAge -lt 0) { 'illimitata' } else { "$policyMaxAge giorni" }) + " (massimo $maxAge)")
    $details.Add("Lunghezza minima: $policyMinLength caratteri (minimo $minLength)")
    $details.Add('Requisiti di complessità: ' + $(if ($complex) { 'attivi' } else { 'disattivati' }) + ' (Windows richiede 3 categorie di caratteri su 4)')
    if ($policyMaxAge -lt 0) { $failures.Add('le password non scadono mai') }
    elseif ($policyMaxAge -gt $maxAge) { $failures.Add("scadenza dopo $policyMaxAge giorni (massimo $maxAge)") }
    if ($policyMinLength -lt $minLength) { $failures.Add("lunghezza minima $policyMinLength (richiesta $minLength)") }
    if ($requireComplexity -and -not $complex) { $failures.Add('complessità disattivata') }
} else {
    $warnings.Add('criterio password non verificabile')
}

$warning = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name PasswordExpiryWarning -ErrorAction SilentlyContinue
$warningDays = if ($warning) { [long]$warning.PasswordExpiryWarning } else { 5 }
$details.Add("Preavviso di scadenza: $warningDays giorni" + $(if ($warning) { '' } else { ' (predefinito)' }) + " (minimo $minWarning)")
if ($warningDays -lt $minWarning) { $failures.Add("preavviso di $warningDays giorni (minimo $minWarning)") }

# Enabled local accounts: "password never expires" violates the requirement.
$neverExpires = 0
$microsoft = 0
$checked = 0
try {
    $accounts = @(Get-LocalUser | Where-Object { $_.Enabled })
    $ordinal = 0
    foreach ($account in $accounts) {
        $ordinal++
        if ("$($account.PrincipalSource)" -eq 'MicrosoftAccount') { $microsoft++; continue }
        $checked++
        if ($null -eq $account.PasswordExpires) {
            $neverExpires++
            $details.Add("Account locale #$ordinal`: password che non scade mai")
        }
    }
    $details.Add("Account locali attivi verificati: $checked; account Microsoft: $microsoft")
} catch {
    $warnings.Add('elenco degli account locali non leggibile')
}
if ($neverExpires -gt 0) { $failures.Add("$neverExpires account con password che non scade mai") }
if ($microsoft -gt 0) { $warnings.Add('gli account Microsoft seguono le regole del loro servizio, non il criterio locale') }

$domain = $false
try { $domain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { }
if ($domain) { $warnings.Add('il computer è in un dominio: il criterio effettivo è quello del dominio') }
$details.Add('Il PIN di Windows Hello ha regole proprie e non è verificato da questo controllo')

if ($failures.Count -gt 0) {
    Out-Result 'FAIL' ('Requisiti password non rispettati: ' + ($failures -join '; ')) $details
}
if ($warnings.Count -gt 0) {
    Out-Result 'WARN' ('Requisiti password locali rispettati, ma: ' + ($warnings -join '; ')) $details
}
Out-Result 'PASS' 'Scadenza, preavviso, lunghezza e complessità delle password rispettano i requisiti' $details
