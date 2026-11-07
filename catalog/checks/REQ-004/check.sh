#!/usr/bin/bash
set -u -o pipefail
id=REQ-004
dir=${BASH_SOURCE[0]%/*}
dnsmasq_status=$("$dir/dnsmasq.sh") || dnsmasq_status='UNKNOWN|script dnsmasq non eseguibile'
hosts_status=$("$dir/hosts.sh") || hosts_status='UNKNOWN|script hosts non eseguibile'
dnsmasq_code=${dnsmasq_status%%|*}
hosts_code=${hosts_status%%|*}

if [[ $dnsmasq_code == ACTIVE ]]; then
  status=PASS
  summary='Il servizio dnsmasq è attivo'
elif [[ $dnsmasq_code == ABSENT && $hosts_code == PRESENT ]]; then
  status=PASS
  summary='Rilevate voci di blocco in /etc/hosts; dnsmasq non è installato'
elif [[ $dnsmasq_code == INACTIVE ]]; then
  status=FAIL
  summary='dnsmasq è installato ma non attivo; /etc/hosts è un fallback solo in assenza di dnsmasq'
elif [[ $dnsmasq_code == ABSENT && $hosts_code == ABSENT ]]; then
  status=FAIL
  summary='Non è stato rilevato alcun metodo DNS supportato'
else
  status=WARN
  summary='Non è stato possibile determinare se il metodo DNS è attivo'
fi
printf '{"id":"%s","status":"%s","summary":"%s","details":["dnsmasq: %s","/etc/hosts: %s","/etc/hosts è considerato solo quando dnsmasq non è installato"]}' \
  "$id" "$status" "$summary" "${dnsmasq_status#*|}" "${hosts_status#*|}"
