#!/usr/bin/bash
set -u -o pipefail
id=REQ-001
if [[ ! -x /usr/bin/checkupdates ]]; then
  printf '{"id":"%s","status":"WARN","summary":"checkupdates non è disponibile; gli aggiornamenti non sono stati controllati","details":["Comando richiesto: /usr/bin/checkupdates","Per abilitarlo: sudo pacman -S --needed pacman-contrib"]}' "$id"
  exit 0
fi
updates=$(/usr/bin/checkupdates --nocolor 2>/dev/null); result=$?
if (( result == 0 )) && [[ -n $updates ]]; then
  count=$(printf '%s\n' "$updates" | /usr/bin/awk 'NF { n++ } END { print n+0 }')
  printf '{"id":"%s","status":"FAIL","summary":"Sono disponibili %s aggiornamenti dei pacchetti","details":["Pacchetti aggiornabili rilevati: %s","checkupdates usa un database temporaneo e può contattare i mirror Arch","Il controllo non valuta la presenza di vulnerabilità"]}' "$id" "$count" "$count"
elif (( result == 2 )); then
  printf '{"id":"%s","status":"PASS","summary":"checkupdates non ha trovato aggiornamenti disponibili","details":["Il risultato dipende dalla disponibilità dei mirror Arch e non verifica vulnerabilità"]}' "$id"
else
  printf '{"id":"%s","status":"WARN","summary":"checkupdates non è riuscito a determinare gli aggiornamenti disponibili","details":[]}' "$id"
fi
