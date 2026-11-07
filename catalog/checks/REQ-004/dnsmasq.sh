#!/usr/bin/bash
# dnsmasq method of REQ-004 (skill audit-postazione R7, method B).
# Output: CODE|detail with CODE in ACTIVE, NOT_ENABLED, NO_RULES, INACTIVE, ABSENT, UNKNOWN.
set -u -o pipefail
min_rules=${1:-1000}
if [[ ! -x /usr/bin/dnsmasq ]]; then
  printf 'ABSENT|pacchetto dnsmasq non installato'
  exit 0
fi
if [[ ! -x /usr/bin/systemctl ]]; then
  printf 'UNKNOWN|dnsmasq installato; stato servizio non determinabile (systemctl non disponibile)'
  exit 0
fi
state=$(/usr/bin/systemctl is-active dnsmasq.service 2>&1); rc=$?
if [[ $state == *'Failed to connect'* || $state == *'Operation not permitted'* || $state == *'System has not been booted'* ]]; then
  printf 'UNKNOWN|dnsmasq installato; stato servizio non determinabile (systemd non interrogabile)'
  exit 0
fi
if ((rc != 0)); then
  printf 'INACTIVE|dnsmasq installato ma servizio non attivo (%s)' "${state:-inactive}"
  exit 0
fi
enabled=$(/usr/bin/systemctl is-enabled dnsmasq.service 2>/dev/null) || true
# Block rules: "server=/domain/" (no upstream) or "address=/domain/0.0.0.0|::|" in the main
# configuration, conf-dir files and every servers-file they reference.
confs=(/etc/dnsmasq.conf /etc/dnsmasq.d/*.conf)
files=()
for conf in "${confs[@]}"; do [[ -r $conf ]] && files+=("$conf"); done
while IFS= read -r extra; do [[ -n $extra ]] && files+=("$extra"); done < <(/usr/bin/awk -F= '$1=="servers-file" {print $2}' "${files[@]}" 2>/dev/null)
rules=0 unreadable=0
for file in "${files[@]}"; do
  if [[ ! -r $file ]]; then ((unreadable+=1)); continue; fi
  count=$(/usr/bin/awk '/^server=\/[^\/]+\/$/ || /^address=\/[^\/]+\/(0\.0\.0\.0|::|#)?$/ {n++} END {print n+0}' "$file" 2>/dev/null) || count=0
  ((rules += count))
done
resolver=$(/usr/bin/awk '$1=="nameserver" {print $2; exit}' /etc/resolv.conf 2>/dev/null)
case $resolver in
  127.*|::1) resolver_note="resolv.conf punta a $resolver (loopback)" ;;
  '') resolver_note="resolv.conf senza nameserver leggibile" ;;
  *) resolver_note="osservazione: resolv.conf non punta a loopback (es. VPN attiva), il filtro locale può essere aggirato" ;;
esac
detail="servizio attivo, enabled=${enabled:-unknown}, $rules regole di blocco (minimo $min_rules), $resolver_note"
if [[ $enabled != enabled ]]; then
  printf 'NOT_ENABLED|%s' "$detail"
elif ((rules < min_rules)); then
  if ((unreadable > 0)); then printf 'UNKNOWN|%s; %s file di regole non leggibili' "$detail" "$unreadable"
  else printf 'NO_RULES|%s' "$detail"; fi
else
  printf 'ACTIVE|%s' "$detail"
fi
