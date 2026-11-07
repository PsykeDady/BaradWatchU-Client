#!/usr/bin/bash
# REQ-007 — automatic screen lock (KDE Plasma 6 on Wayland).
# Criterion (REQUIREMENTS SEC-007): Autolock=true, Timeout <= maxTimeoutMinutes (5),
# LockGrace <= maxLockGraceSeconds (0: password required immediately), LockOnResume=true.
set -u -o pipefail
id=REQ-007
input=''
[[ -t 0 ]] || input=$(/usr/bin/cat 2>/dev/null || true)
read -r max_timeout max_grace <<<"$(printf '%s' "$input" | /usr/bin/python3 -c '
import json, sys
try:
    p = json.load(sys.stdin).get("parameters", {})
except Exception:
    p = {}
print(p.get("maxTimeoutMinutes", 5), p.get("maxLockGraceSeconds", 0))
' 2>/dev/null)"
max_timeout=${max_timeout:-5}
max_grace=${max_grace:-0}
if [[ ! $max_timeout =~ ^[0-9]+$ || ! $max_grace =~ ^[0-9]+$ ]] || ((max_timeout == 0)); then
  printf '{"id":"%s","status":"ERROR","summary":"I parametri maxTimeoutMinutes (>=1) e maxLockGraceSeconds devono essere interi","details":[]}' "$id"
  exit 0
fi
desktop="${XDG_CURRENT_DESKTOP:-} ${DESKTOP_SESSION:-}"
if [[ $desktop != *KDE* && -z ${KDE_SESSION_VERSION:-} ]] && ! /usr/bin/pgrep -u "$(/usr/bin/id -u)" -x kwin_wayland >/dev/null 2>&1; then
  if [[ -n ${XDG_SESSION_TYPE:-} && ${XDG_SESSION_TYPE} != wayland ]]; then
    printf '{"id":"%s","status":"NOT_APPLICABLE","summary":"La sessione grafica attiva non è Plasma Wayland","details":["session-type=%s"]}' "$id" "$XDG_SESSION_TYPE"
  else
    printf '{"id":"%s","status":"WARN","summary":"Non è stato possibile identificare la sessione Plasma attiva","details":["XDG_CURRENT_DESKTOP, KDE_SESSION_VERSION e processo kwin_wayland non disponibili"]}' "$id"
  fi
  exit 0
fi
if [[ ${XDG_SESSION_TYPE:-} == x11 || -z ${WAYLAND_DISPLAY:-} && -n ${DISPLAY:-} ]]; then
  printf '{"id":"%s","status":"NOT_APPLICABLE","summary":"La sessione Plasma attiva non usa Wayland","details":["session-type=%s"]}' "$id" "${XDG_SESSION_TYPE:-unknown}"
  exit 0
fi
if [[ ! -x /usr/bin/kreadconfig6 ]]; then
  printf '{"id":"%s","status":"WARN","summary":"Plasma è rilevato, ma kreadconfig6 non è disponibile per leggere il blocco schermo","details":["Comando richiesto: /usr/bin/kreadconfig6","Per abilitarlo su Arch: sudo pacman -S --needed kconfig"]}' "$id"
  exit 0
fi
# Defaults are Plasma 6 defaults, used when kscreenlockerrc does not set the key.
read_key() { /usr/bin/kreadconfig6 --file kscreenlockerrc --group Daemon --key "$1" --default "$2" 2>/dev/null; }
autolock=$(read_key Autolock true) || autolock=
timeout=$(read_key Timeout 5) || timeout=
grace=$(read_key LockGrace 5) || grace=
resume=$(read_key LockOnResume true) || resume=
details=$(printf '"Autolock=%s","Timeout=%s min (massimo %s)","LockGrace=%s s (massimo %s)","LockOnResume=%s","Fonte: ~/.config/kscreenlockerrc [Daemon] via kreadconfig6"' \
  "${autolock:-?}" "${timeout:-?}" "$max_timeout" "${grace:-?}" "$max_grace" "${resume:-?}")
problems=()
[[ $autolock == false ]] && problems+=("blocco automatico disattivato")
[[ $timeout =~ ^[0-9]+$ ]] && { ((timeout == 0)) && problems+=("timeout 0: blocco automatico disattivato"); ((timeout > max_timeout)) && problems+=("timeout di $timeout minuti oltre il massimo di $max_timeout"); }
[[ $grace =~ ^[0-9]+$ ]] && ((grace > max_grace)) && problems+=("periodo di grazia di $grace secondi: la password non è richiesta subito")
[[ $resume == false ]] && problems+=("blocco alla ripresa dalla sospensione disattivato")
if ((${#problems[@]})); then
  summary="Blocco schermo non conforme: $(IFS=';'; printf '%s' "${problems[*]}" | /usr/bin/sed 's/;/; /g')"
  printf '{"id":"%s","status":"FAIL","summary":"%s","details":[%s]}' "$id" "$summary" "$details"
elif [[ $autolock == true && $timeout =~ ^[1-9][0-9]*$ && $grace =~ ^[0-9]+$ && $resume == true ]]; then
  printf '{"id":"%s","status":"PASS","summary":"Blocco automatico dopo %s minuti con password immediata","details":[%s]}' "$id" "$timeout" "$details"
else
  printf '{"id":"%s","status":"WARN","summary":"Plasma è rilevato, ma le impostazioni di blocco non sono tutte leggibili","details":[%s]}' "$id" "$details"
fi
