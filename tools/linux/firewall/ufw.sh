#!/usr/bin/bash
set -u -o pipefail

unit=/usr/bin/systemctl
ufw=/usr/bin/ufw
config=/etc/ufw/ufw.conf
if [[ ! -x $ufw ]]; then
  printf 'FAIL|ufw=assente'
  exit 0
fi

configured=UNKNOWN
if [[ -r $config ]]; then
  enabled=$(/usr/bin/grep -E '^ENABLED=' "$config" 2>/dev/null | /usr/bin/tail -n 1) || enabled=
  case $enabled in
    ENABLED=yes) configured=yes;;
    ENABLED=no) configured=no;;
    *) configured=UNKNOWN;;
  esac
fi

load=UNKNOWN; active=UNKNOWN; sub=UNKNOWN; result=UNKNOWN; enabled_state=UNKNOWN
show_rc=127; enabled_rc=127
if [[ -x $unit ]]; then
  properties=$($unit show ufw.service -p LoadState -p ActiveState -p SubState -p Result 2>/dev/null); show_rc=$?
  if ((show_rc == 0)); then
    load=$(printf '%s\n' "$properties" | /usr/bin/awk -F= '$1=="LoadState" {print $2}')
    active=$(printf '%s\n' "$properties" | /usr/bin/awk -F= '$1=="ActiveState" {print $2}')
    sub=$(printf '%s\n' "$properties" | /usr/bin/awk -F= '$1=="SubState" {print $2}')
    result=$(printf '%s\n' "$properties" | /usr/bin/awk -F= '$1=="Result" {print $2}')
    [[ -n $load ]] || load=UNKNOWN
    [[ -n $active ]] || active=UNKNOWN
    [[ -n $sub ]] || sub=UNKNOWN
    [[ -n $result ]] || result=UNKNOWN
  fi
  enabled_state=$($unit is-enabled ufw.service 2>/dev/null); enabled_rc=$?
  [[ $enabled_state =~ ^[a-zA-Z0-9_-]+$ ]] || enabled_state=UNKNOWN
fi

status_output=$($ufw status 2>/dev/null); ufw_rc=$?
ufw_state=UNKNOWN
if ((ufw_rc == 0)); then
  case $status_output in
    *'Status: active'*) ufw_state=active;;
    *'Status: inactive'*) ufw_state=inactive;;
  esac
fi

evidence="config=$configured; LoadState=$load; ActiveState=$active; SubState=$sub; Result=$result; is-enabled=$enabled_state (exit $enabled_rc); ufw-status=$ufw_state (exit $ufw_rc)"
if [[ $configured == no ]]; then
  printf 'FAIL|UFW esplicitamente disabilitato; %s' "$evidence"
elif [[ $configured == yes && $load == loaded && $active == active && ( $sub == active || $sub == exited ) && $result == success ]]; then
  printf 'PASS|UFW abilitato e unità attiva (incluse unità oneshot concluse); %s' "$evidence"
elif [[ $configured == yes && $load == loaded && $ufw_state == active ]]; then
  printf 'PASS|UFW abilitato e ufw status conferma il filtraggio attivo; %s' "$evidence"
elif [[ $configured == yes && $load == not-found && $ufw_state == active ]]; then
  printf 'WARN|ufw status è attivo ma l unità systemd non è presente; %s' "$evidence"
elif [[ $load == not-found || $enabled_state == not-found || $enabled_state == masked ]]; then
  printf 'FAIL|unità UFW non disponibile o mascherata; %s' "$evidence"
else
  printf 'WARN|configurazione o stato runtime UFW non sufficienti per provarne l operatività; %s' "$evidence"
fi
