#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-007 — automatic screen lock on macOS (REQUIREMENTS SEC-007), same parameters as Linux:
# maxTimeoutMinutes (default 5) and maxLockGraceSeconds (default 0). Unprivileged sources, for
# the user that runs the audit:
#   - inactivity: screen saver idleTime (configuration profile in /Library/Managed Preferences
#     wins over the user's ByHost preference) and display sleep (pmset -g custom, worst power
#     source); the earliest active one starts the lock;
#   - lock: "require password after screen saver or display off" with its delay
#     (sysadminctl -screenLock status; a profile's askForPassword/askForPasswordDelay wins).
#   PASS: lock required within maxLockGraceSeconds after an inactivity timer of at most
#         maxTimeoutMinutes. FAIL: lock off, delay too long, or no timer within the limit.
#   WARN: the lock setting cannot be read. Apps that keep the display awake (pmset assertions)
#         are reported as an observation.
set -u
id=REQ-007
input=''
[ -t 0 ] || input=$(/bin/cat 2>/dev/null || true)
json_string() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/\\t}; s=${s//$'\r'/\\r}; s=${s//$'\n'/\\n}
  s=$(printf '%s' "$s" | LC_ALL=C /usr/bin/tr -d '\000-\010\013\014\016-\037\177')
  printf '"%s"' "$s"
}
emit() { # STATUS SUMMARY [DETAIL...]
  local status=$1 summary=$2 detail first=1
  shift 2
  printf '{"id":"%s","status":"%s","summary":%s,"details":[' "$id" "$status" "$(json_string "$summary")"
  for detail in "$@"; do
    ((first)) || printf ','
    first=0
    json_string "$detail"
  done
  printf ']}'
  exit 0
}
int_param() { # VARIABLE NAME DEFAULT: a non-negative integer parameter, else ERROR
  local type value=$3
  if [ -n "$input" ] && type=$(printf '%s' "$input" | /usr/bin/plutil -type "parameters.$2" - 2>/dev/null); then
    value=$(printf '%s' "$input" | /usr/bin/plutil -extract "parameters.$2" raw -o - - 2>/dev/null)
    if [ "$type" != integer ] || ! [[ $value =~ ^[0-9]+$ ]]; then
      emit ERROR "$2 deve essere un intero non negativo"
    fi
  fi
  printf -v "$1" '%s' "$value"
}
int_param max_minutes maxTimeoutMinutes 5
int_param max_grace maxLockGraceSeconds 0
max_seconds=$((max_minutes * 60))
user=${USER:-$(/usr/bin/id -un)}
details=()

managed() { # KEY -> value from a screen saver configuration profile (user first, then device)
  local file
  for file in "/Library/Managed Preferences/$user/com.apple.screensaver.plist" '/Library/Managed Preferences/com.apple.screensaver.plist'; do
    [ -r "$file" ] && /usr/bin/plutil -extract "$1" raw -o - "$file" 2>/dev/null && return 0
  done
  return 1
}

# Inactivity timers (seconds; 0 = never).
idle_source='profilo di configurazione'
idle=$(managed idleTime) || {
  idle_source='preferenza utente'
  idle=$(/usr/bin/defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null) || idle=''
}
[[ $idle =~ ^[0-9]+$ ]] || { idle=''; idle_source='non impostato (valore predefinito di sistema)'; }
display=$(/usr/bin/pmset -g custom 2>/dev/null | /usr/bin/awk '$1 == "displaysleep" { if ($2 == 0) never = 1; else if ($2 > max) max = $2 } END { if (never) print 0; else if (max) print max }')
[[ $display =~ ^[0-9]+$ ]] || display=''
timer=''
if [ -n "$idle" ] && ((idle > 0)); then timer=$idle; fi
if [ -n "$display" ] && ((display > 0)); then
  display_seconds=$((display * 60))
  if [ -z "$timer" ] || ((display_seconds < timer)); then timer=$display_seconds; fi
fi
describe() { # SECONDS -> text
  if [ -z "$1" ]; then printf 'non leggibile'
  elif (($1 == 0)); then printf 'mai'
  elif (($1 % 60 == 0)); then printf '%s min' $(($1 / 60))
  else printf '%s s' "$1"; fi
}
details+=("Salvaschermo dopo: $(describe "$idle") ($idle_source)")
details+=("Spegnimento schermo dopo: $(describe "${display_seconds:-${display:+0}}") (pmset, alimentazione più permissiva)")

# Lock after screen saver / display off, and its grace period.
lock_source='profilo di configurazione'
ask=$(managed askForPassword) || ask=''
case $ask in 1|true) lock=on ;; 0|false) lock=off ;; *) lock='' ;; esac
delay=''
if [ "$lock" = on ]; then delay=$(managed askForPasswordDelay) || delay=0; fi
if [ -z "$lock" ]; then
  lock_source='impostazione utente (sysadminctl -screenLock status)'
  text=$(/usr/sbin/sysadminctl -screenLock status 2>&1) || true
  case $text in
    *'screenLock delay is immediate'*) lock=on delay=0 ;;
    *'screenLock delay is '*' seconds'*) lock=on delay=$(printf '%s\n' "$text" | /usr/bin/sed -n 's/.*screenLock delay is \([0-9][0-9]*\) seconds.*/\1/p' | /usr/bin/head -n 1) ;;
    *'screenLock is off'*) lock=off ;;
  esac
fi
delay=${delay%%.*}
case $lock in
  on) details+=("Richiesta password: dopo $(describe "${delay:-0}" | /usr/bin/sed 's/^mai$/0 s/') ($lock_source)") ;;
  off) details+=("Richiesta password: disattivata ($lock_source)") ;;
  *) details+=('Richiesta password: non leggibile') ;;
esac
prevented=$(/usr/bin/pmset -g 2>/dev/null | /usr/bin/sed -n 's/.*display sleep prevented by \(.*\))$/\1/p' | /usr/bin/head -n 1)
[ -n "$prevented" ] && details+=("Osservazione: lo spegnimento dello schermo è attualmente impedito da: $prevented")

if [ -z "$lock" ]; then
  emit WARN 'Non è stato possibile leggere se lo schermo richiede la password' "${details[@]}"
fi
if [ "$lock" = off ]; then
  emit FAIL 'Lo schermo non richiede la password dopo salvaschermo o spegnimento dello schermo' "${details[@]}"
fi
if ! [[ ${delay:-0} =~ ^[0-9]+$ ]] || ((${delay:-0} > max_grace)); then
  emit FAIL "La password è richiesta solo dopo ${delay:-?} s di tolleranza (massimo $max_grace)" "${details[@]}"
fi
if [ -z "$timer" ] || ((timer > max_seconds)); then
  emit FAIL "La sessione non si blocca automaticamente entro $max_minutes minuti" "${details[@]}"
fi
emit PASS "Blocco automatico della sessione dopo $(describe "$timer") di inattività" "${details[@]}"
