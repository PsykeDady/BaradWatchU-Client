#!/usr/bin/bash
set -u -o pipefail
id=REQ-007
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
autolock=$(/usr/bin/kreadconfig6 --file kscreenlockerrc --group Daemon --key Autolock --default true 2>/dev/null) || autolock=
timeout=$(/usr/bin/kreadconfig6 --file kscreenlockerrc --group Daemon --key Timeout --default 5 2>/dev/null) || timeout=
grace=$(/usr/bin/kreadconfig6 --file kscreenlockerrc --group Daemon --key LockGrace --default 5 2>/dev/null) || grace=
resume=$(/usr/bin/kreadconfig6 --file kscreenlockerrc --group Daemon --key LockOnResume --default true 2>/dev/null) || resume=
if [[ $autolock == false || $timeout == 0 ]]; then
  printf '{"id":"%s","status":"FAIL","summary":"Il blocco automatico risulta disabilitato nelle impostazioni Plasma","details":["autolock=%s","timeout-minutes=%s"]}' "$id" "$autolock" "$timeout"
elif [[ $autolock == true && $timeout =~ ^[1-9][0-9]*$ ]]; then
  printf '{"id":"%s","status":"PASS","summary":"Il blocco automatico Plasma è attivo dopo %s minuti","details":["session=Plasma/Wayland","lock-grace=%s","lock-on-resume=%s"]}' "$id" "$timeout" "${grace:-default}" "${resume:-default}"
else
  printf '{"id":"%s","status":"WARN","summary":"Plasma è rilevato, ma le impostazioni personalizzate non permettono di stabilire il timeout effettivo","details":["autolock=%s","timeout-minutes=%s","valori predefiniti Plasma non inclusi nel risultato"]}' "$id" "${autolock:-default}" "${timeout:-default}"
fi
