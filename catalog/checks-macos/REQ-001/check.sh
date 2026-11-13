#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-001 — software updates on macOS (REQUIREMENTS SEC-001: no age threshold, only "no pending
# update"). Source: /usr/sbin/softwareupdate --list --include-config-data (Apple catalog, no
# privileges; macOS, Safari, Command Line Tools and security configuration data such as
# XProtect). Automatic-update preferences are reported as evidence only.
# PASS: Apple reports no available update. FAIL: at least one update is available.
# WARN: the catalog could not be queried (network, proxy, server error) or the output is unknown.
# Not covered: Mac App Store applications, Homebrew and other third-party updaters.
set -u
id=REQ-001
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

details=()
os=$(/usr/bin/sw_vers -productVersion 2>/dev/null) || os=''
build=$(/usr/bin/sw_vers -buildVersion 2>/dev/null) || build=''
[ -n "$os" ] && details+=("macOS $os ($build)")

# Automatic update preferences (evidence only: they do not prove anything was installed).
pref() {
  /usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate "$1" 2>/dev/null || printf 'predefinito'
}
details+=("Aggiornamenti automatici: controllo=$(pref AutomaticCheckEnabled), download=$(pref AutomaticDownload), installazione macOS=$(pref AutomaticallyInstallMacOSUpdates), risposte rapide di sicurezza=$(pref CriticalUpdateInstall), dati di configurazione=$(pref ConfigDataInstall)")

if [ ! -x /usr/sbin/softwareupdate ]; then
  emit WARN 'softwareupdate non è disponibile; gli aggiornamenti non sono stati controllati' ${details[@]+"${details[@]}"}
fi
output=$(/usr/sbin/softwareupdate --list --include-config-data 2>&1)
rc=$?
labels=$(printf '%s\n' "$output" | /usr/bin/sed -n 's/^[[:space:]]*\* Label: //p')
titles=$(printf '%s\n' "$output" | /usr/bin/sed -n 's/^[[:space:]]*Title: \([^,]*\),.*/\1/p')
count=0
[ -n "$labels" ] && count=$(printf '%s\n' "$labels" | /usr/bin/awk 'NF { n++ } END { print n + 0 }')
details+=("softwareupdate exit-code=$rc")
details+=('Non coperti: app del Mac App Store, Homebrew e altri gestori di aggiornamenti di terze parti')

if ((count > 0)); then
  shown=$(printf '%s\n' "${titles:-$labels}" | /usr/bin/head -n 10 | /usr/bin/paste -s -d ';' - | /usr/bin/sed 's/;/; /g')
  details=("Aggiornamenti disponibili ($count): $shown" ${details[@]+"${details[@]}"})
  details+=('Installa con: Impostazioni di Sistema > Generali > Aggiornamento Software (oppure sudo softwareupdate --install --all)')
  emit FAIL "Sono disponibili $count aggiornamenti Apple" "${details[@]}"
fi
if ((rc == 0)) && printf '%s\n' "$output" | /usr/bin/grep -q 'No new software available'; then
  emit PASS 'Il sistema è aggiornato: Apple non segnala aggiornamenti disponibili' "${details[@]}"
fi
excerpt=$(printf '%s\n' "$output" | /usr/bin/grep -v -e '^Software Update Tool' -e '^Finding available software' -e '^[[:space:]]*$' | /usr/bin/head -n 3 | /usr/bin/paste -s -d '|' -)
[ -n "$excerpt" ] && details+=("Output: $excerpt")
emit WARN 'softwareupdate non è riuscito a determinare gli aggiornamenti disponibili (rete o server Apple non raggiungibili?)' "${details[@]}"
