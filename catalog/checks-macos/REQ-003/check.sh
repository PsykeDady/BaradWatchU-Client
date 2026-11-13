#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-003 — host firewall on macOS (REQUIREMENTS SEC-014).
# Source: Application Firewall (socketfilterfw, no privileges): global state, block-all and
# stealth mode. Packet Filter (pf) rules and state need root (pfctl): they are observed only
# through boot-time evidence (a LaunchDaemon that runs pfctl -e, or a non-default /etc/pf.conf).
#   PASS: Application Firewall enabled (State = 1 or 2, also when imposed by a profile).
#   FAIL: Application Firewall disabled and no evidence of a pf configuration.
#   WARN: Application Firewall disabled but pf may be configured (not verifiable without root),
#         or the firewall state cannot be read.
set -u
id=REQ-003
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

alf=/usr/libexec/ApplicationFirewall/socketfilterfw
details=()
if [ ! -x "$alf" ]; then
  emit WARN 'Lo stato del firewall applicativo di macOS non è leggibile' "$alf assente"
fi
global=$("$alf" --getglobalstate 2>&1) || true
state=$(printf '%s\n' "$global" | /usr/bin/sed -n 's/.*(State = \([0-9]\)).*/\1/p' | /usr/bin/head -n 1)
blockall=$("$alf" --getblockall 2>&1) || true
stealth=$("$alf" --getstealthmode 2>&1) || true
case $blockall in *'enabled'*) blockall_label='attivo' ;; *'disabled'*) blockall_label='non attivo' ;; *) blockall_label='non leggibile' ;; esac
case $stealth in *' on'*|*'enabled'*) stealth_label='attiva' ;; *' off'*|*'disabled'*) stealth_label='non attiva' ;; *) stealth_label='non leggibile' ;; esac

# pf evidence without root: boot-time enablement or a customised main ruleset.
pf_evidence=''
for plist in /Library/LaunchDaemons/*.plist; do
  [ -f "$plist" ] || continue
  if /usr/bin/plutil -convert xml1 -o - "$plist" 2>/dev/null | /usr/bin/grep -q 'pfctl'; then
    pf_evidence="LaunchDaemon ${plist##*/} esegue pfctl"
    break
  fi
done
if [ -z "$pf_evidence" ] && [ -r /etc/pf.conf ] &&
  /usr/bin/grep -v -E '^[[:space:]]*(#|$)' /etc/pf.conf | /usr/bin/grep -q -v -E '^[[:space:]]*(scrub-anchor|nat-anchor|rdr-anchor|dummynet-anchor|anchor|load anchor) "com\.apple'; then
  pf_evidence='/etc/pf.conf contiene regole diverse da quelle predefinite di Apple'
fi
pf_label=${pf_evidence:-'nessuna configurazione pf rilevata (regole e stato richiedono root: pfctl -s info)'}

case $state in
  1|2)
    details+=("Firewall applicativo: attivo (State = $state$([ "$state" = 2 ] && printf ', solo servizi essenziali'))")
    details+=("Blocco di tutte le connessioni in entrata: $blockall_label; modalità invisibile: $stealth_label")
    details+=("Packet Filter: $pf_label")
    emit PASS 'Il firewall applicativo di macOS è attivo' "${details[@]}"
    ;;
  0)
    details+=('Firewall applicativo: disattivato (State = 0)')
    details+=("Packet Filter: $pf_label")
    details+=('Attivalo da Impostazioni di Sistema > Rete > Firewall')
    if [ -n "$pf_evidence" ]; then
      emit WARN 'Il firewall applicativo è disattivato; un filtro pf potrebbe essere configurato ma non è verificabile senza privilegi' "${details[@]}"
    fi
    emit FAIL 'Il firewall applicativo di macOS è disattivato' "${details[@]}"
    ;;
esac
emit WARN 'Lo stato del firewall applicativo di macOS non è interpretabile' "socketfilterfw: $(printf '%s' "$global" | /usr/bin/head -n 1)" "Packet Filter: $pf_label"
