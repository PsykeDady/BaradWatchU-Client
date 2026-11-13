#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-002 provider "xprotect": Apple's built-in anti-malware (XProtect), the macOS counterpart of
# the Windows "defender" provider. Unprivileged sources: /usr/bin/xprotect status|version
# (macOS 15+), csrutil status (SIP protects XProtect from tampering), spctl --status (Gatekeeper).
#   FAIL: launch or background scans disabled, SIP or Gatekeeper disabled, definitions older than
#         maxSignatureAgeDays (default 30; Apple publishes XProtect data irregularly).
#   WARN: state not readable (xprotect missing, unknown output, unknown install date).
# Parameters (stdin JSON {"parameters":{...}}): maxSignatureAgeDays.
set -u
id=REQ-002
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
int_param() { # VARIABLE NAME DEFAULT: a non-negative integer parameter, else ERROR
  local type value=$3
  if [ -n "$input" ] && type=$(printf '%s' "$input" | /usr/bin/plutil -type "parameters.$2" - 2>/dev/null); then
    value=$(printf '%s' "$input" | /usr/bin/plutil -extract "parameters.$2" raw -o - - 2>/dev/null)
    if [ "$type" != integer ] || ! [[ $value =~ ^[0-9]+$ ]]; then
      emit ERROR "$2 deve essere un intero non negativo"
    fi
  fi
  printf -v "$1" '%s' "$value"
}

int_param max_age maxSignatureAgeDays 30
details=() problems=() unknown=()

if [ -x /usr/bin/xprotect ]; then
  status_text=$(/usr/bin/xprotect status 2>&1) || true
  launch=$(printf '%s\n' "$status_text" | /usr/bin/sed -n 's/^XProtect launch scans: //p')
  background=$(printf '%s\n' "$status_text" | /usr/bin/sed -n 's/^XProtect background scans: //p')
  details+=("Scansioni all'avvio delle app: ${launch:-non lette}; scansioni in background: ${background:-non lette}")
  case $launch in
    enabled) ;;
    '') unknown+=('stato delle scansioni XProtect non leggibile') ;;
    *) problems+=("scansioni XProtect all'avvio non attive ($launch)") ;;
  esac
  case $background in
    enabled) ;;
    '') unknown+=('stato delle scansioni XProtect in background non leggibile') ;;
    *) problems+=("scansioni XProtect in background non attive ($background)") ;;
  esac
  version_text=$(/usr/bin/xprotect version 2>&1) || true
  version=$(printf '%s\n' "$version_text" | /usr/bin/sed -n 's/^Version: \([0-9][0-9]*\).*/\1/p' | /usr/bin/head -n 1)
  installed=$(printf '%s\n' "$version_text" | /usr/bin/sed -n 's/.*Installed: \([0-9-]* [0-9:]*\).*/\1/p' | /usr/bin/head -n 1)
else
  unknown+=('comando /usr/bin/xprotect assente (disponibile da macOS 15): stato delle scansioni non verificabile')
  plist=/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist
  version=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$plist" 2>/dev/null) || version=''
  installed=''
  [ -f "$plist" ] && installed=$(/bin/date -u -r "$(/usr/bin/stat -f %m "$plist")" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
fi
if [ -n "$installed" ] && epoch=$(/bin/date -j -u -f '%Y-%m-%d %H:%M:%S' "$installed" +%s 2>/dev/null); then
  age=$(( ($(/bin/date +%s) - epoch) / 86400 ))
  details+=("Definizioni XProtect ${version:-?} installate il ${installed%% *} ($age giorni fa; massimo $max_age)")
  ((age <= max_age)) || problems+=("definizioni XProtect non aggiornate da $age giorni (massimo $max_age)")
else
  unknown+=('data di installazione delle definizioni XProtect non leggibile')
fi

sip=$(/usr/bin/csrutil status 2>/dev/null) || sip=''
case $sip in
  *'status: enabled.'*) details+=('System Integrity Protection: attiva (protegge XProtect da modifiche)') ;;
  *'status: disabled.'*) problems+=('System Integrity Protection disattivata: XProtect può essere alterato') ;;
  *) unknown+=('stato di System Integrity Protection non leggibile') ;;
esac
gatekeeper=$(/usr/sbin/spctl --status 2>&1) || true
case $gatekeeper in
  *'assessments enabled'*) details+=('Gatekeeper: valutazioni attive') ;;
  *'assessments disabled'*) problems+=('Gatekeeper disattivato (spctl --status)') ;;
  *) unknown+=('stato di Gatekeeper non leggibile') ;;
esac

join() { local IFS=';'; printf '%s' "$*" | /usr/bin/sed 's/;/; /g'; }
if ((${#problems[@]})); then
  for item in ${unknown[@]+"${unknown[@]}"}; do details+=("non verificato: $item"); done
  emit FAIL "Protezione XProtect non conforme: $(join "${problems[@]}")" "${details[@]}"
fi
if ((${#unknown[@]})); then
  emit WARN "Protezione XProtect non verificabile: $(join "${unknown[@]}")" ${details[@]+"${details[@]}"}
fi
emit PASS 'XProtect attivo con definizioni aggiornate, SIP e Gatekeeper attivi' "${details[@]}"
