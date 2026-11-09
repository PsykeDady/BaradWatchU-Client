#!/usr/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-002 provider "bitdefender-gravityzone": Bitdefender Endpoint Security Tools (BEST) for Linux,
# managed by GravityZone. UNVERIFIED on a real endpoint: written from Bitdefender's public docs
# (install dir /opt/bitdefender-security-tools, systemd units bdsec*, `bduitool get ps` product
# status). Anything that cannot be observed is WARN, never PASS.
#   FAIL: agent not installed, no bdsec* service active or one failed, on-access scanning off,
#         signatures older than maxSignatureAgeDays.
#   WARN: product status unreadable (bduitool may need root), unknown fields, company not verifiable.
# Parameters (stdin JSON {"parameters":{...}}): maxSignatureAgeDays (default 3),
# expectedCompanyId (default "": not checked), installDir (default /opt/bitdefender-security-tools).
set -u -o pipefail
id=REQ-002
input=''
[[ -t 0 ]] || input=$(/usr/bin/cat 2>/dev/null || true)

emit() { # status summary details...
  /usr/bin/python3 -c '
import json, sys
print(json.dumps({"id": sys.argv[1], "status": sys.argv[2], "summary": sys.argv[3], "details": sys.argv[4:]}, ensure_ascii=False))
' "$id" "$@"
  exit 0
}

read -r max_age install_dir company <<<"$(printf '%s' "$input" | /usr/bin/python3 -c '
import json, sys
try:
    p = json.load(sys.stdin).get("parameters", {}) or {}
except Exception:
    p = {}
age = p.get("maxSignatureAgeDays", 3)
d = p.get("installDir", "/opt/bitdefender-security-tools")
c = p.get("expectedCompanyId", "")
ok = isinstance(age, int) and not isinstance(age, bool) and age >= 0 and isinstance(d, str) and d.startswith("/") \
    and " " not in d and isinstance(c, str) and " " not in c
print(age if ok else "invalid", d if ok else "-", c if (ok and c) else "-")
' 2>/dev/null)"
if [[ ! ${max_age:-} =~ ^[0-9]+$ ]]; then
  emit ERROR 'Parametri non validi: maxSignatureAgeDays intero ≥ 0, installDir percorso assoluto, expectedCompanyId stringa senza spazi'
fi
[[ $company == - ]] && company=''
note='Provider basato sulla documentazione pubblica Bitdefender: da validare su un endpoint reale'
details=()

if [[ ! -d $install_dir ]]; then
  emit FAIL 'Bitdefender GravityZone non risulta installato' "cartella $install_dir assente" "$note"
fi
details+=("installazione: $install_dir")
problems=() unknown=()

# Services: BEST installs systemd units named bdsec* (docs: `systemctl status bdsec*`). Unit
# files are listed even when disabled/not loaded; the main unit is bdsec.service.
files=$(/usr/bin/systemctl list-unit-files --type=service --no-legend --plain 'bdsec*' 2>&1); rc=$?
if ((rc != 0)) && [[ $files == *'Failed to connect'* || $files == *'System has not been booted'* ]]; then
  unknown+=('stato dei servizi bdsec* non leggibile')
else
  active=0 seen=0 main=''
  while read -r unit file_state _; do
    [[ $unit == bdsec*.service ]] || continue
    [[ $file_state == static ]] && continue
    seen=$((seen + 1))
    state=$(/usr/bin/systemctl is-active "$unit" 2>/dev/null)
    details+=("servizio $unit: ${state:-sconosciuto}, avvio ${file_state}")
    [[ $state == active ]] && active=$((active + 1))
    [[ $state == failed ]] && problems+=("servizio $unit in errore")
    [[ $unit == bdsec.service ]] && main="$state/$file_state"
  done <<<"$files"
  if ((seen == 0)); then problems+=('nessun servizio bdsec* installato')
  elif ((active == 0)); then problems+=('nessun servizio bdsec* attivo')
  elif [[ -n $main && $main != active/enabled ]]; then problems+=("servizio principale bdsec.service non attivo o non abilitato all’avvio ($main)"); fi
fi
version=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version",""))' "$install_dir/etc/manifest.json" 2>/dev/null)
[[ -n $version ]] && details+=("versione installata: $version")

# Product status: `bduitool get ps` (field names unverified). It needs root: it aborts when it
# cannot write its own log, so it is only run when that log folder is writable.
tool=''
for candidate in "$install_dir/bin/bduitool" /opt/BitDefender/bin/bduitool; do
  [[ -x $candidate ]] && { tool=$candidate; break; }
done
status_text=''
if [[ -z $tool ]]; then
  unknown+=('bduitool non trovato: stato del prodotto non verificabile')
elif [[ ! -w ${tool%/bin/bduitool}/var/log ]]; then
  unknown+=('stato del prodotto (bduitool get ps) leggibile solo con privilegi di root')
else
  status_text=$(LC_ALL=C /usr/bin/timeout 20 "$tool" get ps 2>&1); rc=$?
  if ((rc != 0)) || [[ -z $status_text ]]; then
    unknown+=("bduitool get ps non riuscito (codice $rc)")
    status_text=''
  fi
fi

if [[ -n $status_text ]]; then
  antimalware=$(printf '%s\n' "$status_text" | /usr/bin/awk -F': *' 'tolower($1) ~ /antimalware|on-access/ {print tolower($2); exit}')
  case $antimalware in
    on*|enabled*|active*) details+=("scansione on-access: $antimalware") ;;
    off*|disabled*|inactive*) problems+=("scansione on-access disattivata ($antimalware)") ;;
    *) unknown+=('stato della scansione on-access non riconosciuto nell’output di bduitool') ;;
  esac
  update=$(printf '%s\n' "$status_text" | /usr/bin/awk -F': *' 'tolower($1) ~ /update/ {sub(/^[^:]*: */, ""); print; exit}')
  update_epoch=''
  [[ -n $update ]] && update_epoch=$(/usr/bin/date -d "$update" +%s 2>/dev/null)
  if [[ $update_epoch =~ ^[0-9]+$ ]]; then
    age=$((($(/usr/bin/date +%s) - update_epoch) / 86400))
    details+=("ultimo aggiornamento: $update ($age giorni; massimo $max_age)")
    ((age <= max_age)) || problems+=("firme non aggiornate da $age giorni (massimo $max_age)")
  else
    unknown+=('data dell’ultimo aggiornamento non riconosciuta')
  fi
fi

if [[ -n $company ]]; then
  if [[ -n $status_text && $status_text == *"$company"* ]]; then
    details+=("azienda GravityZone attesa trovata: $company")
  else
    unknown+=("appartenenza all’azienda GravityZone $company non verificabile")
  fi
fi

join() { local IFS=';'; printf '%s' "$*" | /usr/bin/sed 's/;/; /g'; }
if ((${#problems[@]})); then
  emit FAIL "Bitdefender GravityZone non conforme: $(join "${problems[@]}")" "${details[@]}" "${unknown[@]/#/non verificato: }" "$note"
elif ((${#unknown[@]})); then
  emit WARN "Bitdefender GravityZone installato ma non verificabile: $(join "${unknown[@]}")" "${details[@]}" "$note"
fi
emit PASS 'Bitdefender GravityZone attivo: servizi, scansione on-access e firme aggiornate' "${details[@]}" "$note"
