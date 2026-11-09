#!/usr/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-004 — DNS filter (REQUIREMENTS SEC-004, skill audit-postazione R7).
# PASS when at least one supported method is fully in place:
#   A) /etc/hosts HaGeZi blocklist (operator decision 2026-11-08), complete as declared by its
#      header, with >= minimumHostsEntries names (default 10000) and not older than
#      maxListAgeDays (default 30; older = inconclusive); requireHagezi=false accepts any list;
#   B) dnsmasq active + enabled with >= minimumDnsmasqRules block rules (default 1000).
# FAIL when every method is observably missing or incomplete; WARN when undeterminable.
set -u -o pipefail
id=REQ-004
dir=${BASH_SOURCE[0]%/*}
input=''
[[ -t 0 ]] || input=$(/usr/bin/cat 2>/dev/null || true)
read -r min_hosts min_rules max_age require_hagezi <<<"$(printf '%s' "$input" | /usr/bin/python3 -c '
import json, sys
try:
    p = json.load(sys.stdin).get("parameters", {})
except Exception:
    p = {}
r = p.get("requireHagezi", True)
print(p.get("minimumHostsEntries", 10000), p.get("minimumDnsmasqRules", 1000), p.get("maxListAgeDays", 30),
      "true" if r is True else "false" if r is False else "invalid")
' 2>/dev/null)"
min_hosts=${min_hosts:-10000} min_rules=${min_rules:-1000} max_age=${max_age:-30} require_hagezi=${require_hagezi:-true}
if [[ ! $min_hosts =~ ^[0-9]+$ || ! $min_rules =~ ^[0-9]+$ || ! $max_age =~ ^[0-9]+$ || ! $require_hagezi =~ ^(true|false)$ ]]; then
  printf '{"id":"%s","status":"ERROR","summary":"minimumHostsEntries, minimumDnsmasqRules e maxListAgeDays devono essere interi, requireHagezi true o false","details":[]}' "$id"
  exit 0
fi
dnsmasq_status=$("$dir/dnsmasq.sh" "$min_rules") || dnsmasq_status='UNKNOWN|script dnsmasq non eseguibile'
hosts_status=$("$dir/hosts.sh" "$min_hosts" "$max_age" "$require_hagezi") || hosts_status='UNKNOWN|script hosts non eseguibile'
dnsmasq_code=${dnsmasq_status%%|*}
hosts_code=${hosts_status%%|*}

if [[ $dnsmasq_code == ACTIVE && $hosts_code == PRESENT ]]; then
  status=PASS summary='Filtro DNS attivo con entrambi i metodi: dnsmasq e blocklist in /etc/hosts'
elif [[ $dnsmasq_code == ACTIVE ]]; then
  status=PASS summary='Filtro DNS attivo: dnsmasq in esecuzione, abilitato all’avvio e con regole di blocco caricate'
elif [[ $hosts_code == PRESENT ]]; then
  status=PASS summary='Filtro DNS attivo: blocklist completa in /etc/hosts'
elif [[ $hosts_code == STALE ]]; then
  status=WARN summary='La lista HaGeZi in /etc/hosts è presente ma non aggiornata di recente'
elif [[ $dnsmasq_code == UNKNOWN || $hosts_code == UNKNOWN ]]; then
  status=WARN summary='Non è stato possibile determinare se un metodo di filtro DNS è attivo'
else
  status=FAIL
  case $dnsmasq_code in
    NOT_ENABLED) summary='dnsmasq è attivo ma non abilitato all’avvio e /etc/hosts non contiene una blocklist completa' ;;
    NO_RULES) summary='dnsmasq è attivo ma senza regole di blocco sufficienti e /etc/hosts non contiene una blocklist completa' ;;
    INACTIVE) summary='dnsmasq è installato ma non attivo e /etc/hosts non contiene una blocklist completa' ;;
    *)
      case $hosts_code in
        NOT_HAGEZI) summary='/etc/hosts contiene voci di blocco ma non una lista HaGeZi riconoscibile' ;;
        INCOMPLETE) summary='La lista HaGeZi in /etc/hosts è incompleta rispetto alle voci dichiarate' ;;
        *) summary='Nessun metodo di filtro DNS supportato è attivo (dnsmasq o blocklist in /etc/hosts)' ;;
      esac
      ;;
  esac
fi
printf '{"id":"%s","status":"%s","summary":"%s","details":["Metodo B dnsmasq: %s","Metodo A /etc/hosts: %s","È sufficiente uno dei due metodi"]}' \
  "$id" "$status" "$summary" "${dnsmasq_status#*|}" "${hosts_status#*|}"
