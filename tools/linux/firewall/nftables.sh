#!/usr/bin/bash
set -u -o pipefail

systemctl=/usr/bin/systemctl
nft=/usr/bin/nft
active=UNKNOWN; enabled=UNKNOWN; active_rc=127; enabled_rc=127
if [[ -x $systemctl ]]; then
  active=$($systemctl is-active nftables.service 2>/dev/null); active_rc=$?
  enabled=$($systemctl is-enabled nftables.service 2>/dev/null); enabled_rc=$?
  [[ $active =~ ^[a-zA-Z0-9_-]+$ ]] || active=UNKNOWN
  [[ $enabled =~ ^[a-zA-Z0-9_-]+$ ]] || enabled=UNKNOWN
fi
evidence="nftables.service is-active=$active (exit $active_rc); is-enabled=$enabled (exit $enabled_rc)"

if [[ ! -x $nft ]]; then
  printf 'WARN|nft non disponibile; lo stato del ruleset kernel non è determinabile; %s' "$evidence"
  exit 0
fi

rules=$($nft list ruleset 2>/dev/null); nft_rc=$?
evidence+="; nft list ruleset=exit $nft_rc"
if ((nft_rc != 0)); then
  printf 'WARN|ruleset non leggibile senza privilegi; non sono state tentate escalation; %s' "$evidence"
  exit 0
fi
if [[ -z ${rules//[[:space:]]/} ]]; then
  printf 'FAIL|ruleset nftables vuoto; nessun filtro kernel verificato; %s' "$evidence"
  exit 0
fi

read -r input_chains drop_chains <<< "$(printf '%s\n' "$rules" | /usr/bin/awk '
function finish_chain() {
  if (in_chain && is_input) {
    inputs++
    if (policy == "drop") drops++
  }
}
/^[[:space:]]*chain[[:space:]]+/ {
  finish_chain()
  in_chain=1
  is_input=0
  policy=""
  next
}
in_chain && /hook[[:space:]]+input([[:space:];]|$)/ {is_input=1}
in_chain && /policy[[:space:]]+(drop|accept)([[:space:];]|$)/ {
  if (match($0, /policy[[:space:]]+(drop|accept)/)) {
    value=substr($0, RSTART, RLENGTH)
    sub(/^.*policy[[:space:]]+/, "", value)
    policy=value
  }
}
/^[[:space:]]*}[[:space:]]*$/ {finish_chain(); in_chain=0}
END {finish_chain(); printf "%d %d\n", inputs+0, drops+0}
')"
if [[ $input_chains =~ ^[0-9]+$ && $drop_chains == "$input_chains" ]] && ((input_chains > 0)); then
  printf 'PASS|tutte le chain base INPUT rilevate hanno policy drop (%s); %s' "$input_chains" "$evidence"
elif [[ $input_chains =~ ^[0-9]+$ ]] && ((input_chains > 0)); then
  printf 'WARN|ruleset leggibile ma non tutte le chain INPUT hanno policy drop verificabile (%s/%s); %s' "$drop_chains" "$input_chains" "$evidence"
else
  printf 'WARN|ruleset leggibile ma senza chain base INPUT identificabili; %s' "$evidence"
fi
