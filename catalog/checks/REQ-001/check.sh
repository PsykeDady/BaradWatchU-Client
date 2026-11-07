#!/usr/bin/bash
# REQ-001 — software updates on Arch Linux (skill audit-postazione R6).
# Criterion: checkupdates (pacman-contrib) reports 0 pending updates from the official
# repositories. The age of the last full upgrade from pacman.log is reported as evidence.
# AUR packages are not covered. checkupdates syncs a temporary DB and contacts mirrors.
set -u -o pipefail
id=REQ-001
last_upgrade='ultimo full system upgrade non rilevato in /var/log/pacman.log'
if [[ -r /var/log/pacman.log ]]; then
  stamp=$(/usr/bin/grep -a 'starting full system upgrade' /var/log/pacman.log 2>/dev/null | /usr/bin/tail -n1 | /usr/bin/sed -n 's/^\[\([^]]*\)\].*/\1/p')
  if [[ -n $stamp ]] && epoch=$(/usr/bin/date -d "$stamp" +%s 2>/dev/null); then
    now=$(/usr/bin/date +%s)
    last_upgrade="ultimo full system upgrade: $(/usr/bin/date -d "@$epoch" +%Y-%m-%d) ($(((now-epoch)/86400)) giorni fa)"
  fi
fi
if [[ ! -x /usr/bin/checkupdates ]]; then
  printf '{"id":"%s","status":"WARN","summary":"checkupdates non è disponibile; gli aggiornamenti non sono stati controllati","details":["Comando richiesto: /usr/bin/checkupdates","Per abilitarlo: sudo pacman -S --needed pacman-contrib","%s"]}' "$id" "$last_upgrade"
  exit 0
fi
updates=$(/usr/bin/checkupdates --nocolor 2>/dev/null); result=$?
if (( result == 0 )) && [[ -n $updates ]]; then
  count=$(printf '%s\n' "$updates" | /usr/bin/awk 'NF { n++ } END { print n+0 }')
  printf '{"id":"%s","status":"FAIL","summary":"Sono disponibili %s aggiornamenti dei pacchetti","details":["Pacchetti aggiornabili rilevati: %s","%s","Aggiorna con: sudo pacman -Syu","checkupdates copre i repository ufficiali, non AUR"]}' "$id" "$count" "$count" "$last_upgrade"
elif (( result == 2 )); then
  printf '{"id":"%s","status":"PASS","summary":"Il sistema è allineato ai repository ufficiali: nessun aggiornamento disponibile","details":["%s","checkupdates copre i repository ufficiali, non AUR; il controllo non valuta vulnerabilità"]}' "$id" "$last_upgrade"
else
  printf '{"id":"%s","status":"WARN","summary":"checkupdates non è riuscito a determinare gli aggiornamenti disponibili (mirror non raggiungibili?)","details":["checkupdates exit-code=%s","%s"]}' "$id" "$result" "$last_upgrade"
fi
