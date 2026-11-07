#!/usr/bin/bash
set -u -o pipefail

systemctl=/usr/bin/systemctl
firewall_cmd=/usr/bin/firewall-cmd
active=UNKNOWN; enabled=UNKNOWN; active_rc=127; enabled_rc=127
if [[ -x $systemctl ]]; then
  active=$($systemctl is-active firewalld.service 2>/dev/null); active_rc=$?
  enabled=$($systemctl is-enabled firewalld.service 2>/dev/null); enabled_rc=$?
  [[ $active =~ ^[a-zA-Z0-9_-]+$ ]] || active=UNKNOWN
  [[ $enabled =~ ^[a-zA-Z0-9_-]+$ ]] || enabled=UNKNOWN
fi

state=UNKNOWN; state_rc=127
if [[ -x $firewall_cmd ]]; then
  state=$($firewall_cmd --state 2>/dev/null); state_rc=$?
  [[ $state == running || $state == 'not running' ]] || state=UNKNOWN
fi
evidence="firewalld.service is-active=$active (exit $active_rc); is-enabled=$enabled (exit $enabled_rc); firewall-cmd --state=$state (exit $state_rc)"

if [[ $state == running && $active == active ]]; then
  printf 'PASS|firewalld operativo; %s' "$evidence"
elif [[ $state == running && $active != inactive && $active != failed && $active != not-found ]]; then
  printf 'PASS|firewall-cmd conferma firewalld operativo; %s' "$evidence"
elif [[ $state == 'not running' && ( $active == inactive || $active == failed || $active == not-found ) ]]; then
  printf 'FAIL|firewalld non operativo; %s' "$evidence"
elif [[ $state == 'not running' ]]; then
  printf 'WARN|firewall-cmd e systemd riportano evidenze discordanti; %s' "$evidence"
elif [[ ! -x $firewall_cmd && ( $active == inactive || $active == failed || $active == not-found ) && ( $enabled == disabled || $enabled == not-found || $enabled == masked ) ]]; then
  printf 'FAIL|firewalld non operativo e firewall-cmd non disponibile; %s' "$evidence"
elif [[ $active == not-found && $enabled == not-found && ! -x $firewall_cmd ]]; then
  printf 'FAIL|firewalld e firewall-cmd non sono installati; %s' "$evidence"
else
  printf 'WARN|operatività firewalld non determinabile con le evidenze disponibili; %s' "$evidence"
fi
