#!/usr/bin/env bash
# BaradWatchU system service (Milestone 2) on Linux (systemd) and macOS (launchd).
# Internal component: install.sh calls it during installation, update and uninstall (in
# the step that already runs as root); it can also be run by hand. It installs nothing but
# the service definition. It never generates keys, starts a Server connection,
# never changes firewall rules and never removes registrations or user data.
set -euo pipefail
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
AGENT='' MODE=install DRY_RUN=0
UNIT=/etc/systemd/system/baradwatchu-agent.service
PLIST=/Library/LaunchDaemons/io.baradwatchu.agent.plist
LABEL=io.baradwatchu.agent
VERIFY_SECONDS=${BARADWATCHU_SERVICE_VERIFY_TIMEOUT:-10}
STOP_WAITED=0 STOP_ACTIVE='' STOP_PID=''

usage() { cat <<'EOF'
Usage: sudo packaging/service/install-service.sh [--agent=PATH] [--dry-run]
       sudo packaging/service/install-service.sh --uninstall|--stop|--start [--agent=PATH] [--dry-run]
       packaging/service/install-service.sh --status

Normally run by install.sh: every system installation, update and uninstall includes it.

  (default)     Install or update the service (systemd unit baradwatchu-agent.service,
                LaunchDaemon io.baradwatchu.agent), enable it at boot and (re)start it,
                then check that the running process is exactly PATH (never an old copy).
  --agent=PATH  Installed baradwatchu-agent (default: /usr/local/bin/baradwatchu-agent,
                else the one in PATH). It runs as root, so it and every parent folder must
                be owned by root and not writable by others: per-user copies are refused.
                With --uninstall/--stop/--start: act only when the service runs PATH.
  --uninstall   Stop and remove the service. Registrations and request records in
                /var/lib/baradwatchu (macOS: /Library/Application Support/BaradWatchU/
                service) and every user's identity are kept.
  --stop        Stop the service (it stays installed and enabled at boot).
  --start       Start the installed service and check the running executable.
  --status      Print "absent" or "installed PATH active|inactive" (no root needed).
  --dry-run     Print the plan only.

Each user enables remote requests and starts trusted Server connections from the
Client dashboard. Firewall rules are left to the operator/IT.
EOF
}

for arg; do
    case $arg in
        --agent=*) AGENT=${arg#--agent=} ;;
        --uninstall) MODE=uninstall ;;
        --stop) MODE=stop ;;
        --start) MODE=start ;;
        --status) MODE=status ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Error: unknown option $arg" >&2; usage >&2; exit 2 ;;
    esac
done
[[ $VERIFY_SECONDS =~ ^[1-9][0-9]?$ ]] || { echo 'BARADWATCHU_SERVICE_VERIFY_TIMEOUT must be 1-99 seconds' >&2; exit 2; }

fail() { echo "Error: $*" >&2; exit 1; }
run() { if ((DRY_RUN)); then printf '  would run:'; printf ' %q' "$@"; echo; else "$@"; fi; }

case $(uname -s) in
    Linux) OS=linux; command -v systemctl >/dev/null || fail 'systemd (systemctl) is required' ;;
    Darwin) OS=macos ;;
    *) fail 'this script supports Linux (systemd) and macOS; on Windows use install-service.ps1' ;;
esac

# Agent of the installed service, from the definition we wrote ('' = not installed).
installed_agent() {
    if [[ $OS == linux ]]; then
        [[ -f $UNIT ]] || return 0
        sed -n 's/^ExecStart=\(.*\) service run$/\1/p' "$UNIT" | head -n 1
    else
        [[ -f $PLIST ]] || return 0
        /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$PLIST" 2>/dev/null || true
    fi
}
service_pid() { # PID of the running service, empty when it is not running
    local pid
    if [[ $OS == linux ]]; then
        pid=$(systemctl show -p MainPID --value baradwatchu-agent.service 2>/dev/null || true)
    else
        pid=$(launchctl print "system/$LABEL" 2>/dev/null | sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' | head -n 1)
    fi
    [[ $pid =~ ^[1-9][0-9]*$ ]] && printf '%s\n' "$pid"
    return 0
}
running_executable() { # executable of PID; "(deleted)" marks a replaced (obsolete) file
    if [[ $OS == linux ]]; then readlink -- "/proc/$1/exe" 2>/dev/null || true
    else ps -o comm= -p "$1" 2>/dev/null || true; fi
}

if [[ $MODE == status ]]; then
    current=$(installed_agent)
    if [[ -z $current ]]; then echo absent
    elif [[ -n $(service_pid) ]]; then echo "installed $current active"
    else echo "installed $current inactive"; fi
    exit 0
fi
((DRY_RUN)) || [[ $EUID -eq 0 ]] || fail 'run as root (sudo); use --dry-run to preview'

owner_of() { if [[ $OS == macos ]]; then stat -f %u -- "$1"; else stat -c %u -- "$1"; fi; }
mode_of() { if [[ $OS == macos ]]; then stat -f %Lp -- "$1"; else stat -c %a -- "$1"; fi; }

# A root service must not run a binary a user could replace.
check_root_owned() {
    local path=$1
    while :; do
        [[ $(owner_of "$path") == 0 ]] || fail "$path is not owned by root"
        (( (8#$(mode_of "$path") & 8#022) == 0 )) || fail "$path is writable by group or others"
        [[ $path == / ]] && break
        path=$(dirname -- "$path")
    done
}

# The service must run exactly AGENT: a running process whose file was replaced (an update
# without restart) or another executable is an error, never a silent success.
verify_running() {
    local agent=$1 pid exe waited=0 last_exe=''
    ((DRY_RUN)) && { echo "  would check that the running service is $agent"; return 0; }
    while ((waited < VERIFY_SECONDS * 10)); do
        pid=$(service_pid)
        if [[ -n $pid ]]; then
            exe=$(running_executable "$pid")
            last_exe=$exe
            if [[ $exe == "$agent" ]]; then
                sleep 0.5   # still alive after start-up (configuration read, endpoint open)?
                [[ $(service_pid) == "$pid" ]] && { echo "  running:  PID $pid ($agent)"; return 0; }
            fi
        fi
        sleep 0.1; waited=$((waited + 1))
    done
    if [[ -n $last_exe && $last_exe != "$agent" ]]; then
        fail "the service did not switch to $agent during start-up (last MainPID executable: $last_exe)"
    fi
    if [[ $OS == linux ]]; then
        fail "the service did not stay running; see: systemctl status baradwatchu-agent.service; journalctl -u baradwatchu-agent.service"
    fi
    fail "the service did not stay running; see: launchctl print system/$LABEL"
}

current=$(installed_agent)
# --agent with uninstall/stop/start: only the service of that installation is touched.
if [[ $MODE != install ]]; then
    if [[ -z $current ]]; then echo "Service not installed."; exit 0; fi
    if [[ -n $AGENT && $current != "$AGENT" ]]; then
        echo "Service left unchanged: it runs $current, not $AGENT."
        exit 0
    fi
fi

case $MODE in
    stop)
        if [[ $OS == linux ]]; then
            run systemctl stop baradwatchu-agent.service
            if ((!DRY_RUN)); then
                STOP_WAITED=0 STOP_ACTIVE='' STOP_PID=''
                while ((STOP_WAITED < VERIFY_SECONDS * 10)); do
                    STOP_ACTIVE=$(systemctl is-active baradwatchu-agent.service 2>/dev/null || true)
                    STOP_PID=$(service_pid)
                    [[ $STOP_ACTIVE != active && -z $STOP_PID ]] && break
                    sleep 0.1; STOP_WAITED=$((STOP_WAITED + 1))
                done
                [[ $STOP_ACTIVE != active && -z $STOP_PID ]] || fail "systemd service did not stop (state: ${STOP_ACTIVE:-unknown}, MainPID: ${STOP_PID:-none}); refusing to replace its executable"
            fi
        else run launchctl bootout "system/$LABEL" 2>/dev/null || true; fi
        echo "Service stopped (still installed)."
        exit 0 ;;
    start)
        if [[ $OS == linux ]]; then run systemctl start baradwatchu-agent.service
        else run launchctl bootstrap system "$PLIST" 2>/dev/null || run launchctl kickstart "system/$LABEL"; fi
        verify_running "$current"
        exit 0 ;;
    uninstall)
        if [[ $OS == linux ]]; then
            run systemctl disable --now baradwatchu-agent.service
            run rm -f -- "$UNIT"
            run systemctl daemon-reload
            run systemctl reset-failed baradwatchu-agent.service 2>/dev/null || true
        else
            run launchctl bootout "system/$LABEL" 2>/dev/null || true
            run rm -f -- "$PLIST"
        fi
        echo "Service removed. Registrations and request records are kept in the service data folder; user identities are untouched."
        exit 0 ;;
esac

if [[ -z $AGENT ]]; then
    if [[ -x /usr/local/bin/baradwatchu-agent ]]; then AGENT=/usr/local/bin/baradwatchu-agent
    else AGENT=$(command -v baradwatchu-agent || true); fi
fi
[[ -n $AGENT ]] || fail 'baradwatchu-agent not found: install the Client first or pass --agent=PATH'
[[ $AGENT == /* ]] || AGENT=$PWD/$AGENT
AGENT=$(cd -- "$(dirname -- "$AGENT")" && pwd -P)/$(basename -- "$AGENT")
[[ -f $AGENT && -x $AGENT && ! -L $AGENT ]] || fail "$AGENT is not an executable file"
[[ $AGENT != *[$'\n'\"\'\\\ \#\&]* ]] || fail "unsupported characters in $AGENT"
check_root_owned "$AGENT"
"$AGENT" --version >/dev/null || fail "$AGENT does not run"
{ "$AGENT" service 2>&1 || true; } | grep -q 'service run' || fail "$AGENT predates the system service: reinstall the Client first"

echo "BaradWatchU system service"
echo "  agent:    $AGENT"
[[ -z $current || $current == "$AGENT" ]] || echo "  replaces: service that ran $current"
if [[ $OS == linux ]]; then
    echo "  unit:     $UNIT (enabled at boot, restarted on failure)"
    echo "  data:     /var/lib/baradwatchu (user connections start only when enabled)"
    rendered=$(sed "s#@AGENT@#$AGENT#" "$HERE/baradwatchu-agent.service")
    if ((DRY_RUN)); then echo "  would write $UNIT"; else
        tmp=$(mktemp "$UNIT.XXXXXX")
        printf '%s\n' "$rendered" > "$tmp"
        chmod 0644 "$tmp"; chown 0:0 "$tmp"
        mv -f -- "$tmp" "$UNIT"
    fi
    run systemctl daemon-reload
    run systemctl enable baradwatchu-agent.service
    # restart, not "enable --now": an already running service must load the new executable.
    run systemctl restart baradwatchu-agent.service
else
    echo "  daemon:   $PLIST (started at boot, kept alive)"
    echo "  data:     /Library/Application Support/BaradWatchU/service"
    rendered=$(sed "s#@AGENT@#$AGENT#" "$HERE/io.baradwatchu.agent.plist")
    run launchctl bootout "system/$LABEL" 2>/dev/null || true
    if ((DRY_RUN)); then echo "  would write $PLIST"; else
        tmp=$(mktemp "$PLIST.XXXXXX")
        printf '%s\n' "$rendered" > "$tmp"
        chmod 0644 "$tmp"; chown 0:0 "$tmp"
        mv -f -- "$tmp" "$PLIST"
    fi
    run launchctl bootstrap system "$PLIST"
fi
verify_running "$AGENT"
echo "Service ready. Each user enables remote requests and starts trusted Server connections from the Client dashboard (after identity generate)."
