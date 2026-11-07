#!/usr/bin/bash
set -u -o pipefail
id=REQ-005
dir=${BASH_SOURCE[0]%/*}
cato=$("$dir/cato.sh") || cato=UNKNOWN
wireguard=$("$dir/wireguard.sh") || wireguard=UNKNOWN
[[ $cato == *'|'* ]] || cato='UNKNOWN|script Cato non interpretabile'
[[ $wireguard == *'|'* ]] || wireguard='UNKNOWN|script WireGuard non interpretabile'
cato_state=${cato%%|*}
wireguard_state=${wireguard%%|*}

if [[ $cato_state == CONNECTED || $wireguard_state == CONNECTED ]]; then
  status=PASS
  summary='Almeno una VPN supportata risulta connessa'
elif [[ $cato_state == UNKNOWN || $wireguard_state == UNKNOWN || $cato_state == DISCONNECTED || $wireguard_state == DISCONNECTED ]]; then
  status=WARN
  summary='La VPN è presente ma disconnessa, oppure il suo stato non è determinabile'
else
  status=FAIL
  summary='Non è stato rilevato alcun client VPN supportato'
fi
printf '{"id":"%s","status":"%s","summary":"%s","details":["Cato: %s","WireGuard: %s"]}' \
  "$id" "$status" "$summary" "${cato#*|}" "${wireguard#*|}"
