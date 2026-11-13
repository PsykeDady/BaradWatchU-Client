#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-002 provider "bitdefender-gravityzone": Bitdefender Endpoint Security Tools (BEST) for Mac,
# managed by GravityZone. Verified on a real endpoint (BEST 8.26.11, macOS 27, Apple silicon).
# Unprivileged evidence only (nothing is started, stopped or reconfigured):
#   - installation: BDLDaemon.app under installDir and the "Endpoint Security for Mac" app;
#   - code signature: valid, Developer ID of Bitdefender SRL (team GUNFMW623Y);
#   - running: the LaunchDaemon that starts BDLDaemon is "running" in launchd and its process
#     runs exactly that executable (Endpoint Security client entitlement reported as evidence);
#   - signatures: active engine (signatures/engine/engines.plist) Plugins/update.txt
#     "Update time GMT" not older than maxSignatureAgeDays;
#   - web protection: Bitdefender network system extension state (evidence only).
# Not verifiable without privileges: on-access (real-time) scanning state and GravityZone company
# (product settings are encrypted; productConfigurationTool -asksForStatus is root-only). These
# are reported as unverified, so a healthy installation is WARN, never PASS (REQUIREMENTS §5.1).
#   FAIL: not installed, invalid/foreign signature, daemon not running, signatures too old.
# Parameters (stdin JSON {"parameters":{...}}): maxSignatureAgeDays (default 3),
# expectedCompanyId (default "": not checked), installDir (default /Library/Bitdefender/AVP).
set -u
id=REQ-002
team=GUNFMW623Y
input=''
[ -t 0 ] || input=$(/bin/cat 2>/dev/null || true)
json_string() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/\\t}; s=${s//$'\r'/\\r}; s=${s//$'\n'/\\n}
  s=$(printf '%s' "$s" | LC_ALL=C /usr/bin/tr -d '\000-\010\013\014\016-\037\177')
  printf '"%s"' "$s"
}
emit() { # STATUS SUMMARY [DETAIL...]
  local status=$1 summary=$2 detail first=1
  shift 2
  printf '{"id":"%s","status":"%s","summary":%s,"details":[' "$id" "$status" "$(json_string "$summary")"
  for detail in "$@"; do
    ((first)) || printf ','
    first=0
    json_string "$detail"
  done
  printf ']}'
  exit 0
}
param_type() { [ -n "$input" ] && printf '%s' "$input" | /usr/bin/plutil -type "parameters.$1" - 2>/dev/null; }
param_raw() { printf '%s' "$input" | /usr/bin/plutil -extract "parameters.$1" raw -o - - 2>/dev/null; }
int_param() { # VARIABLE NAME DEFAULT: a non-negative integer parameter, else ERROR
  local type value=$3
  if type=$(param_type "$2"); then
    value=$(param_raw "$2")
    if [ "$type" != integer ] || ! [[ $value =~ ^[0-9]+$ ]]; then
      emit ERROR "$2 deve essere un intero non negativo"
    fi
  fi
  printf -v "$1" '%s' "$value"
}
string_param() { # VARIABLE NAME DEFAULT
  local type value=$3
  if type=$(param_type "$2"); then
    [ "$type" = string ] || emit ERROR "$2 deve essere una stringa"
    value=$(param_raw "$2")
  fi
  printf -v "$1" '%s' "$value"
}

int_param max_age maxSignatureAgeDays 3
string_param company expectedCompanyId ''
string_param install_dir installDir /Library/Bitdefender/AVP
details=() problems=() unknown=()
daemon_app="$install_dir/product/bin/BDLDaemon.app"
daemon_exe="$daemon_app/Contents/MacOS/BDLDaemon"
app='/Applications/Endpoint Security for Mac.app'

if [ ! -f "$daemon_exe" ]; then
  emit FAIL 'Bitdefender Endpoint Security Tools non risulta installato' "$daemon_exe assente" \
    'Provider basato sulle interfacce di BEST per Mac 8.x'
fi
version=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist" 2>/dev/null) ||
  version=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$daemon_app/Contents/Info.plist" 2>/dev/null) || version='?'
details+=("Installato: Bitdefender Endpoint Security Tools $version ($install_dir)")

# Code signature: a valid Developer ID signature of Bitdefender SRL, not just a folder name.
if /usr/bin/codesign --verify --strict "$daemon_app" >/dev/null 2>&1; then
  signer=$(/usr/bin/codesign -dv "$daemon_app" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=//p')
  if [ "$signer" = "$team" ]; then
    details+=("Firma del codice di BDLDaemon valida (Developer ID Bitdefender SRL, team $team)")
  else
    problems+=("BDLDaemon firmato da un team inatteso (${signer:-sconosciuto}, atteso $team)")
  fi
else
  problems+=('firma del codice di BDLDaemon non valida')
fi
if /usr/bin/codesign -d --entitlements - "$daemon_app" 2>/dev/null | /usr/bin/grep -q 'endpoint-security.client'; then
  details+=('BDLDaemon è un client Endpoint Security di macOS (entitlement presente)')
fi

# Running daemon: the LaunchDaemon whose program is BDLDaemon, as seen by launchd.
label=''
for plist in /Library/LaunchDaemons/*.plist; do
  [ -f "$plist" ] || continue
  program=$(/usr/bin/plutil -extract Program raw -o - "$plist" 2>/dev/null) ||
    program=$(/usr/bin/plutil -extract ProgramArguments.0 raw -o - "$plist" 2>/dev/null) || continue
  if [ "$program" = "$daemon_exe" ]; then
    label=$(/usr/bin/plutil -extract Label raw -o - "$plist" 2>/dev/null) || label=''
    break
  fi
done
if [ -z "$label" ]; then
  problems+=('nessun LaunchDaemon avvia BDLDaemon')
else
  info=$(/bin/launchctl print "system/$label" 2>/dev/null) || info=''
  state=$(printf '%s\n' "$info" | /usr/bin/sed -n 's/^[[:space:]]*state = //p' | /usr/bin/head -n 1)
  pid=$(printf '%s\n' "$info" | /usr/bin/sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' | /usr/bin/head -n 1)
  if [ -z "$info" ]; then
    problems+=("servizio launchd $label non caricato")
  elif [ "$state" = running ] && [ -n "$pid" ]; then
    exe=$(/bin/ps -o comm= -p "$pid" 2>/dev/null) || exe=''
    if [ "$exe" = "$daemon_exe" ]; then
      details+=("Servizio launchd $label in esecuzione (PID $pid)")
    else
      problems+=("il processo del servizio $label non esegue BDLDaemon (${exe:-processo non leggibile})")
    fi
  else
    problems+=("servizio launchd $label non in esecuzione (stato ${state:-sconosciuto})")
  fi
fi

# Signatures of the active engine.
engines="$install_dir/signatures/engine/engines.plist"
active=$(/usr/bin/plutil -extract active raw -o - "$engines" 2>/dev/null) || active=''
update_file="$active/Plugins/update.txt"
if [ -n "$active" ] && [ -r "$update_file" ]; then
  stamp=$(/usr/bin/sed -n 's/^Update time GMT: \([0-9][0-9]*\).*/\1/p' "$update_file" | /usr/bin/head -n 1)
  number=$(/usr/bin/sed -n 's/^Signature number: \([0-9][0-9]*\).*/\1/p' "$update_file" | /usr/bin/head -n 1)
  engine=$(/usr/bin/sed -n 's/^Version: //p' "$update_file" | /usr/bin/head -n 1)
  if [ -n "$stamp" ]; then
    age=$(( ($(/bin/date +%s) - stamp) / 86400 ))
    when=$(/bin/date -u -r "$stamp" '+%Y-%m-%d %H:%M UTC')
    details+=("Ultimo aggiornamento firme: $when ($age giorni; massimo $max_age), firme ${number:-?}, motore ${engine:-?}")
    ((age <= max_age)) || problems+=("firme non aggiornate da $age giorni (massimo $max_age)")
  else
    unknown+=('data di aggiornamento delle firme non riconosciuta')
  fi
else
  unknown+=('motore antivirus attivo o file update.txt non leggibile')
fi

# Web/traffic protection network extension (evidence only).
extensions=$(/usr/bin/systemextensionsctl list 2>/dev/null | /usr/bin/grep "$team" | /usr/bin/grep -c '\[activated enabled\]')
if [ "${extensions:-0}" -gt 0 ]; then
  details+=('Estensione di rete Bitdefender (protezione traffico web) attiva')
else
  details+=('Estensione di rete Bitdefender non attiva (protezione del traffico web non disponibile)')
fi

unknown+=('stato della scansione in tempo reale (on-access) non leggibile senza privilegi: impostazioni del prodotto cifrate e productConfigurationTool riservato a root')
[ -n "$company" ] && unknown+=("appartenenza all'azienda GravityZone $company non verificabile")

join() { local IFS=';'; printf '%s' "$*" | /usr/bin/sed 's/;/; /g'; }
if ((${#problems[@]})); then
  for item in "${unknown[@]}"; do details+=("non verificato: $item"); done
  emit FAIL "Bitdefender GravityZone non conforme: $(join "${problems[@]}")" "${details[@]}"
fi
emit WARN "Bitdefender GravityZone installato e in esecuzione, ma non verificabile: $(join "${unknown[@]}")" "${details[@]}"
