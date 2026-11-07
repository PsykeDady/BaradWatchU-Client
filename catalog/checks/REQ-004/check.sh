#!/usr/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-004 — DNS filter (REQUIREMENTS SEC-004, skill audit-postazione R7).
# PASS when at least one supported method is fully in place:
#   A) /etc/hosts blocklist with >= minimumHostsEntries entries (default 10000);
#   B) dnsmasq active + enabled with >= minimumDnsmasqRules block rules (default 1000).
# FAIL when every method is observably missing or incomplete; WARN when undeterminable.
set -u -o pipefail
id=REQ-004
dir=${BASH_SOURCE[0]%/*}
input=''
[[ -t 0 ]] || input=$(/usr/bin/cat 2>/dev/null || true)
read -r min_hosts min_rules <<<"$(printf '%s' "$input" | /usr/bin/python3 -c '
import json, sys
try:
    p = json.load(sys.stdin).get("parameters", {})
except Exception:
    p = {}
print(p.get("minimumHostsEntries", 10000), p.get("minimumDnsmasqRules", 1000))
' 2>/dev/null)"
min_hosts=${min_hosts:-10000} min_rules=${min_rules:-1000}
if [[ ! $min_hosts =~ ^[0-9]+$ || ! $min_rules =~ ^[0-9]+$ ]]; then
  printf '{"id":"%s","status":"ERROR","summary":"minimumHostsEntries e minimumDnsmasqRules devono essere interi","details":[]}' "$id"
  exit 0
fi
dnsmasq_status=$("$dir/dnsmasq.sh" "$min_rules") || dnsmasq_status='UNKNOWN|script dnsmasq non eseguibile'
hosts_status=$("$dir/hosts.sh" "$min_hosts") || hosts_status='UNKNOWN|script hosts non eseguibile'
dnsmasq_code=${dnsmasq_status%%|*}
hosts_code=${hosts_status%%|*}

if [[ $dnsmasq_code == ACTIVE && $hosts_code == PRESENT ]]; then
  status=PASS summary='Filtro DNS attivo con entrambi i metodi: dnsmasq e blocklist in /etc/hosts'
elif [[ $dnsmasq_code == ACTIVE ]]; then
  status=PASS summary='Filtro DNS attivo: dnsmasq in esecuzione, abilitato all’avvio e con regole di blocco caricate'
elif [[ $hosts_code == PRESENT ]]; then
  status=PASS summary='Filtro DNS attivo: blocklist completa in /etc/hosts'
elif [[ $dnsmasq_code == UNKNOWN || $hosts_code == UNKNOWN ]]; then
  status=WARN summary='Non è stato possibile determinare se un metodo di filtro DNS è attivo'
else
  status=FAIL
  case $dnsmasq_code in
    NOT_ENABLED) summary='dnsmasq è attivo ma non abilitato all’avvio e /etc/hosts non contiene una blocklist completa' ;;
    NO_RULES) summary='dnsmasq è attivo ma senza regole di blocco sufficienti e /etc/hosts non contiene una blocklist completa' ;;
    INACTIVE) summary='dnsmasq è installato ma non attivo e /etc/hosts non contiene una blocklist completa' ;;
    *) summary='Nessun metodo di filtro DNS supportato è attivo (dnsmasq o blocklist in /etc/hosts)' ;;
  esac
fi
printf '{"id":"%s","status":"%s","summary":"%s","details":["Metodo B dnsmasq: %s","Metodo A /etc/hosts: %s","È sufficiente uno dei due metodi"]}' \
  "$id" "$status" "$summary" "${dnsmasq_status#*|}" "${hosts_status#*|}"
