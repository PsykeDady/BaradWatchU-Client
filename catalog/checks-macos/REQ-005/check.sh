#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-005 — corporate VPN on macOS (REQUIREMENTS SEC-011), same supported clients and outcome
# rule as Linux: Cato and WireGuard. Source: the system VPN configurations (scutil --nc list,
# Network Extension VPNs registered by the vendor apps; no privileges) and the app bundles.
#   PASS: a supported VPN is Connected. WARN: a supported VPN is installed/configured but not
#   connected, or its state is not readable. FAIL: no supported VPN client is installed.
# Other VPN configurations are listed as evidence only. Cato's own CLI is not used.
set -u
id=REQ-005
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

list=$(/usr/sbin/scutil --nc list 2>/dev/null) || list=''
# "* (Connected)  UUID VPN (com.vendor.bundle) "Name"  [VPN:com.vendor.bundle]" -> STATE|TYPE
entries=$(printf '%s\n' "$list" | /usr/bin/sed -n 's/^[* ]*(\([^)]*\)).*\[VPN:\([^]]*\)\].*/\1|\2/p')

app_version() { # BUNDLE -> version or empty
  /usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$1/Contents/Info.plist" 2>/dev/null
}
# vendor STATE-VARIABLE LABEL TYPE-PATTERN APP...
vendor() {
  local variable=$1 label=$2 pattern=$3 state=ABSENT detail='' app version line type conn
  shift 3
  for app in "$@"; do
    if [ -d "$app" ]; then
      version=$(app_version "$app")
      detail="app installata (${app##*/} ${version:-?})"
      state=DISCONNECTED
      break
    fi
  done
  while IFS='|' read -r conn type; do
    [ -n "$type" ] || continue
    case $type in $pattern) ;; *) continue ;; esac
    detail="${detail:+$detail, }configurazione di sistema $type: $conn"
    if [ "$conn" = Connected ]; then state=CONNECTED
    elif [ "$state" != CONNECTED ]; then state=DISCONNECTED; fi
  done <<EOF
$entries
EOF
  [ -n "$detail" ] || detail='non installato'
  printf -v "$variable" '%s|%s: %s' "$state" "$label" "$detail"
}
vendor cato Cato 'com.catonetworks.*' /Applications/CatoClient.app '/Applications/Cato Client.app'
vendor wireguard WireGuard 'com.wireguard.*' /Applications/WireGuard.app
others=$(printf '%s\n' "$entries" | /usr/bin/awk -F'|' 'NF == 2 && $2 !~ /^com\.(catonetworks|wireguard)\./ { print $2 " (" $1 ")" }' | /usr/bin/sort -u | /usr/bin/paste -s -d ';' - | /usr/bin/sed 's/;/; /g')

cato_state=${cato%%|*}
wireguard_state=${wireguard%%|*}
if [ "$cato_state" = CONNECTED ] || [ "$wireguard_state" = CONNECTED ]; then
  status=PASS summary='Almeno una VPN supportata risulta connessa'
elif [ "$cato_state" = DISCONNECTED ] || [ "$wireguard_state" = DISCONNECTED ]; then
  status=WARN summary='La VPN è presente ma disconnessa, oppure il suo stato non è determinabile'
else
  status=FAIL summary='Non è stato rilevato alcun client VPN supportato'
fi
details=("${cato#*|}" "${wireguard#*|}")
[ -n "$others" ] && details+=("Altre VPN configurate (non valutate): $others")
[ -n "$list" ] || details+=('Elenco delle VPN di sistema non leggibile (scutil --nc list)')
emit "$status" "$summary" "${details[@]}"
