#!/usr/bin/bash
set -u -o pipefail
id=REQ-002
if ! /usr/bin/pacman -Q clamav >/dev/null 2>&1; then
  printf '{"id":"%s","status":"FAIL","summary":"ClamAV non risulta installato","details":["pacman -Q clamav non ha trovato il pacchetto"]}' "$id"
  exit 0
fi

active_unit() {
  local unit
  for unit in "$@"; do
    local response rc
    response=$(/usr/bin/systemctl is-active "$unit" 2>&1); rc=$?
    if ((rc == 0)); then printf 'active:%s' "$unit"; return 0; fi
    if [[ $response == *'Failed to connect'* || $response == *'Operation not permitted'* || $response == *'System has not been booted'* ]]; then
      printf 'unknown'
      return 0
    fi
  done
  printf 'inactive'
}
daemon_state=$(active_unit clamav-daemon.service clamd@scan.service clamd.service)
updater_state=$(active_unit clamav-freshclam.service freshclam.service)
onaccess_state=$(active_unit clamav-clamonacc.service clamonacc.service)
daemon=${daemon_state%%:*}; daemon_unit=${daemon_state#*:}
updater=${updater_state%%:*}; updater_unit=${updater_state#*:}
onaccess=${onaccess_state%%:*}; onaccess_unit=${onaccess_state#*:}
daemon_label=$daemon; [[ $daemon == active ]] && daemon_label="$daemon ($daemon_unit)"
updater_label=$updater; [[ $updater == active ]] && updater_label="$updater ($updater_unit)"
onaccess_label=$onaccess; [[ $onaccess == active ]] && onaccess_label="$onaccess ($onaccess_unit)"

config=''; prevention=unknown; paths=0
for candidate in /etc/clamav/clamd.conf /etc/clamd.d/scan.conf /etc/clamd.conf; do
  if [[ -r $candidate ]]; then config=$candidate; break; fi
done
if [[ -n $config ]]; then
  prevention=$(/usr/bin/awk '$1=="OnAccessPrevention" {v=$2} END {print tolower(v)}' "$config")
  paths=$(/usr/bin/awk '$1=="OnAccessIncludePath" || $1=="OnAccessMountPath" {n++} END {print n+0}' "$config")
fi

sig_dir=/var/lib/clamav
sig_age=unknown
newest=0
for sig in "$sig_dir"/daily.cvd "$sig_dir"/daily.cld; do
  [[ -f $sig ]] || continue
  mtime=$(/usr/bin/stat -c %Y -- "$sig" 2>/dev/null) || continue
  if [[ $mtime =~ ^[0-9]+$ ]] && ((mtime > newest)); then newest=$mtime; fi
done
if ((newest > 0)); then
  now=$(/usr/bin/date +%s)
  if [[ $now =~ ^[0-9]+$ ]] && ((now >= newest)); then sig_age=$(((now-newest)/86400)); fi
fi

status=WARN
summary='ClamAV è installato; vedere i dettagli per le prove mancanti'
if [[ $daemon == active && $updater == active && $onaccess == active && $prevention == yes && $paths -gt 0 && $sig_age =~ ^[0-9]+$ ]] && ((sig_age <= 3)); then
  status=PASS
  summary='Motore, aggiornamento firme e scansione on-access risultano attivi; database firme aggiornato'
elif [[ $daemon == unknown || $updater == unknown || $onaccess == unknown ]]; then
  status=WARN
  summary='Non è possibile interrogare systemd; lo stato dei servizi ClamAV non è determinabile in questo ambiente'
elif [[ $daemon != active ]]; then
  status=FAIL
  summary='Il motore ClamAV non risulta attivo; verificare daemon e servizio systemd'
elif [[ $updater != active || $onaccess != active ]]; then
  summary='Il servizio ClamAV è attivo, ma aggiornamento firme o scansione in accesso non risultano entrambi attivi'
elif [[ $prevention != yes || $paths -eq 0 ]]; then
  summary='Il servizio ClamAV è attivo, ma la configurazione di prevenzione o i percorsi da sorvegliare non sono dimostrati'
elif [[ ! $sig_age =~ ^[0-9]+$ ]] || ((sig_age > 3)); then
  summary='Il servizio ClamAV è attivo, ma la freschezza delle firme non è verificata o supera 3 giorni'
fi

printf '{"id":"%s","status":"%s","summary":"%s","details":["daemon=%s%s","updater=%s%s","on-access=%s%s","prevention=%s","on-access-paths=%s","età firme giornaliere (giorni)=%s","Soglia firme: massimo 3 giorni; copertura effettiva delle directory non è attestata"]}' \
  "$id" "$status" "$summary" "$daemon_label" "" "$updater_label" "" \
  "$onaccess_label" "" "$prevention" "$paths" "$sig_age"
