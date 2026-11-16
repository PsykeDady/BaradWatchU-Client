#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-004 — DNS filter on macOS (REQUIREMENTS SEC-004), same methods and parameters as Linux:
#   A) /etc/hosts HaGeZi blocklist, complete as declared by its header, with
#      >= minimumHostsEntries names and not older than maxListAgeDays (older = inconclusive);
#      requireHagezi=false accepts any list (macOS resolves through /etc/hosts first);
#   B) dnsmasq (Homebrew/MacPorts) running, started at boot by a LaunchDaemon, with
#      >= minimumDnsmasqRules block rules.
# PASS when one method is fully in place; FAIL when every method is observably missing or
# incomplete; WARN when undeterminable. DNS configured by profiles, VPN clients or browsers
# (encrypted DNS) is not evaluated.
set -u
id=REQ-004
dir=$(cd "$(/usr/bin/dirname "$0")" && pwd -P)
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
invalid() {
  emit ERROR 'minimumHostsEntries, minimumDnsmasqRules e maxListAgeDays devono essere interi, requireHagezi true o false'
}
int_param() { # VARIABLE NAME DEFAULT
  local type value=$3
  if type=$(param_type "$2"); then
    value=$(param_raw "$2")
    { [ "$type" = integer ] && [[ $value =~ ^[0-9]+$ ]]; } || invalid
  fi
  printf -v "$1" '%s' "$value"
}
int_param min_hosts minimumHostsEntries 10000
int_param min_rules minimumDnsmasqRules 1000
int_param max_age maxListAgeDays 30
require_hagezi=true
if type=$(param_type requireHagezi); then
  [ "$type" = bool ] || invalid
  require_hagezi=$(param_raw requireHagezi)
fi

dnsmasq_status=$("$dir/dnsmasq.sh" "$min_rules") || dnsmasq_status='UNKNOWN|script dnsmasq non eseguibile'
hosts_status=$("$dir/hosts.sh" "$min_hosts" "$max_age" "$require_hagezi") || hosts_status='UNKNOWN|script hosts non eseguibile'
dnsmasq_code=${dnsmasq_status%%|*}
hosts_code=${hosts_status%%|*}

if [ "$dnsmasq_code" = ACTIVE ] && [ "$hosts_code" = PRESENT ]; then
  status=PASS summary='Filtro DNS attivo con entrambi i metodi: dnsmasq e blocklist in /etc/hosts'
elif [ "$dnsmasq_code" = ACTIVE ]; then
  status=PASS summary='Filtro DNS attivo: dnsmasq in esecuzione, avviato al boot e con regole di blocco caricate'
elif [ "$hosts_code" = PRESENT ]; then
  status=PASS summary='Filtro DNS attivo: blocklist completa in /etc/hosts'
elif [ "$hosts_code" = STALE ]; then
  status=WARN summary='La lista HaGeZi in /etc/hosts è presente ma non aggiornata di recente'
elif [ "$dnsmasq_code" = UNKNOWN ] || [ "$hosts_code" = UNKNOWN ]; then
  status=WARN summary='Non è stato possibile determinare se un metodo di filtro DNS è attivo'
else
  status=FAIL
  case $dnsmasq_code in
    NOT_ENABLED) summary='dnsmasq è in esecuzione ma non avviato al boot e /etc/hosts non contiene una blocklist completa' ;;
    NO_RULES) summary='dnsmasq è in esecuzione ma senza regole di blocco sufficienti e /etc/hosts non contiene una blocklist completa' ;;
    INACTIVE) summary='dnsmasq è installato ma non in esecuzione e /etc/hosts non contiene una blocklist completa' ;;
    *)
      case $hosts_code in
        NOT_HAGEZI) summary='/etc/hosts contiene voci di blocco ma non una lista HaGeZi riconoscibile' ;;
        INCOMPLETE) summary='La lista HaGeZi in /etc/hosts è incompleta rispetto alle voci dichiarate' ;;
        *) summary='Nessun metodo di filtro DNS supportato è attivo (dnsmasq o blocklist in /etc/hosts)' ;;
      esac
      ;;
  esac
fi
emit "$status" "$summary" "Metodo B dnsmasq: ${dnsmasq_status#*|}" "Metodo A /etc/hosts: ${hosts_status#*|}" 'È sufficiente uno dei due metodi'
