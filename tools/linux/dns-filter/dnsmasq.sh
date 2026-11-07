#!/usr/bin/bash
set -u -o pipefail
if [[ ! -x /usr/bin/dnsmasq ]]; then
  printf 'ABSENT|pacchetto dnsmasq non installato'
  exit 0
fi
if [[ ! -x /usr/bin/systemctl ]]; then
  printf 'UNKNOWN|dnsmasq installato; stato servizio non determinabile (systemctl non disponibile)'
  exit 0
fi
state=$(/usr/bin/systemctl is-active dnsmasq.service 2>&1); rc=$?
if ((rc == 0)); then
  printf 'ACTIVE|dnsmasq installato e servizio attivo'
elif [[ $state == *'Failed to connect'* || $state == *'Operation not permitted'* || $state == *'System has not been booted'* ]]; then
  printf 'UNKNOWN|dnsmasq installato; stato servizio non determinabile (systemd non interrogabile)'
else
  printf 'INACTIVE|dnsmasq installato ma servizio non attivo'
fi
