#!/bin/bash
# BaradWatchU Client source installer for macOS: the port of install.sh (same options, plan,
# build cache, manifest ownership, running-instance and service lifecycle). Written for the
# bash 3.2 shipped with macOS (/bin/bash) and BSD tools; no Homebrew package is required at
# run time. Differences from install.sh are macOS mechanisms, listed in README "macOS".
set -Eeuo pipefail
umask 022
PRODUCT=Client BIN=baradwatchu-agent TRAY_BIN=baradwatchu-tray
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
SELF="$ROOT/install-macos.sh"
VERSION=$(awk '/^[[:space:]]*\[workspace[.]package\]/{f=1;next} /^[[:space:]]*\[/{f=0} f&&/^[[:space:]]*version[[:space:]]*=/{split($0,a,"\"");print a[2];exit}' "$ROOT/Cargo.toml")
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo 'Invalid SemVer in Cargo.toml' >&2; exit 1; }
# Binaries are built for this minimum macOS (MACOSX_DEPLOYMENT_TARGET); the built-in checks
# rely on tools present since the same release (plutil -type, system_profiler -json).
MACOS_MIN=13.0
PREFIX=/usr/local BUILD_DIR=${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/baradwatchu/$BIN-$VERSION
LOCAL=0 UNINSTALL=0 DRY=0 NO_BUILD=0 BUILD_ONLY=0 MISSING=0 PREFIX_SET=0 BUILD_SET=0 REEXEC=0
# Tray companion (baradwatchu-tray): built and installed unless --without-tray.
# Start at login: enabled by default on a first installation (FRESH: no manifest yet); a
# reinstall keeps the user's choice; --tray-autostart forces it, --no-tray-autostart skips it.
WITH_TRAY=1 TRAY_AUTOSTART=0 NO_TRAY_AUTOSTART=0 TRAY_SET=0 FRESH=0
# Two modes. System installation (root-owned prefix, default /usr/local): the complete
# Client, system service included (packaging/service/install-service.sh, LaunchDaemon
# io.baradwatchu.agent, run in the step that already uses sudo). Per-user installation
# (--local, or a prefix writable without root): everything usable without privileges, no
# system service, no remote communication.
SYSTEM_INSTALL=1
SERVICE_SCRIPT="$ROOT/packaging/service/install-service.sh"
SERVICE_LABEL=io.baradwatchu.agent
TRAY_LABEL=io.baradwatchu.tray
SERVICE_ACTION=none SERVICE_NOTE='' SERVICE_CURRENT='' SERVICE_ACTIVE=0 SERVICE_STOPPED=0 SERVICE_PHASE=0
STAGE_DIR='' WEB_BUILD_DIR=''
cleanup() {
    local path
    restore_service
    for path in "$STAGE_DIR" "$WEB_BUILD_DIR"; do
        if [[ -n "$path" && -d "$path" && ! -L "$path" ]]; then find "$path" -depth -delete 2>/dev/null || true; fi
    done
}
trap cleanup EXIT
# Keep execution failures distinct from invalid CLI arguments (exit 2).
trap 'exit 1' ERR
usage() { cat <<'EOF'
BaradWatchU Client source installer (macOS)
Usage: ./install-macos.sh [OPTIONS]
  -h, --help           Show help       -V, --version       Show version
      --missing-deps   Read-only dependency check: [REQUIRED] items block the
                       install, [optional] items only degrade checks
      --dry-run        Print plan without changing files/services
      --no-build       Reuse a validated source/platform/version build
      --build-only     Build and validate cache; do not install files
      --build-dir=DIR  Select build cache outside source tree
      --local          Limited user development copy in ~/.local
      --prefix=DIR     Install prefix (default /usr/local)
  -U, --uninstall      Remove unchanged files listed in source manifest
      --without-tray   Do not build/install the baradwatchu-tray companion
      --tray-autostart Start the tray at login for the invoking user (LaunchAgent
                       ~/Library/LaunchAgents/io.baradwatchu.tray.plist; no root
                       needed), also on a reinstall
      --no-tray-autostart  Do not enable it on a first installation. By
                       default a first installation enables start at login and
                       a reinstall keeps the user's choice (tray menu: Avvia al login)
Two installation modes:
  system (default; a prefix that needs root, such as /usr/local): the complete
    Client - agent, dashboard, tray and the system service (LaunchDaemon
    io.baradwatchu.agent, root) that opens outbound remote mTLS tunnels. Install,
    update and uninstall always include the service.
  per-user (--local, or a --prefix writable without root): agent, dashboard,
    tray, identity, trust store, local audits and reports, without privileges;
    no system service and no remote communication.
Run as a normal user: build without root, then use sudo only to copy files into
a protected system prefix and, in that same step, to install, update or remove
the system service with packaging/service/install-service.sh. Failed sudo
authentication leaves the build cache available for retry. No package is
installed. The service is stopped before its files change and restarted on the
new executable afterwards (checked); if the installation fails it is restarted
on the files in place. Nothing generates keys, starts a Server connection
or changes firewall rules. Each user enables remote requests and starts a
trusted Server connection from the Client dashboard.
Before files are replaced or removed, a running baradwatchu-agent or tray of the
same installation (matched by executable path, e.g. an open dashboard) gets
SIGTERM and up to BARADWATCHU_STOP_TIMEOUT seconds (default 10); it is never killed.
The tray companion runs in the user's login session, never as a service. The
application BaradWatchU.app (/Applications for the system installation,
~/Applications per user; Launchpad and Spotlight) starts the tray when it is not
running and opens the dashboard: no terminal is needed after installation.
Uninstall removes the app and the invoking user's tray LaunchAgent when they
belong to this installation.
EOF
}
fail() { echo "Error: $*" >&2; exit 1; }
badarg() { echo "Error: $*" >&2; usage >&2; exit 2; }
ge() { awk -v a="$1" -v b="$2" 'BEGIN{split(a,x,".");split(b,y,".");for(i=1;i<=3;i++){if(x[i]+0>y[i]+0)exit 0;if(x[i]+0<y[i]+0)exit 1}exit 0}'; }
sha256() { /usr/bin/shasum -a 256 -- "$1" | awk '{print $1}'; }

# Runs an nvm command with errexit, nounset and the ERR trap disabled, then restores them.
nvm_unguarded() {
    local status=0
    set +eEu; trap - ERR
    "$@" || status=$?
    set -eEu; trap 'exit 1' ERR
    return "$status"
}
load_nvm() {
    local nvm_home nvm_script
    declare -F nvm >/dev/null && return 0
    if [[ -n "${NVM_DIR:-}" ]]; then
        nvm_home=$NVM_DIR
    elif [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
        nvm_home=$XDG_CONFIG_HOME/nvm
    else
        nvm_home=${HOME:-}/.nvm
    fi
    if [[ -s "$nvm_home/nvm.sh" ]]; then
        nvm_script=$nvm_home/nvm.sh
    elif [[ -s /opt/homebrew/opt/nvm/nvm.sh ]]; then
        nvm_script=/opt/homebrew/opt/nvm/nvm.sh
    elif [[ -s /usr/local/opt/nvm/nvm.sh ]]; then
        nvm_script=/usr/local/opt/nvm/nvm.sh
    else
        return 1
    fi
    export NVM_DIR=$nvm_home
    # nvm.sh is not written for "set -eu" (bash 3.2 also applies errexit and the ERR trap inside
    # the sourced file despite "|| :"): source it with both off.
    nvm_unguarded source "$nvm_script" >/dev/null 2>&1 || :
    declare -F nvm >/dev/null
}

select_node_from_nvm() {
    local original_dir=$PWD version configured_prefix=${PREFIX-} had_prefix=0 nvm_status=0
    [[ ${PREFIX+x} ]] && had_prefix=1
    load_nvm || return 1
    cd "$ROOT/web" || return 1
    # nvm reserves PREFIX for its own install setting; restore the installer's
    # destination immediately after nvm has selected the Node runtime.
    unset PREFIX
    nvm_unguarded nvm use --silent >/dev/null 2>&1 || nvm_status=$?
    if ((had_prefix)); then PREFIX=$configured_prefix; fi
    if ((nvm_status != 0)); then cd "$original_dir" || return 1; return 1; fi
    cd "$original_dir" || return 1
    version=$(node -p 'process.versions.node' 2>/dev/null) || return 1
    [[ "$version" == 20.* ]] && ge "$version" 20.11.1
}

if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    C_OK=$'\e[32m' C_REQ=$'\e[1;31m' C_OPT=$'\e[33m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RST=$'\e[0m'
else
    C_OK='' C_REQ='' C_OPT='' C_BOLD='' C_DIM='' C_RST=''
fi
section() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RST"; }
dep_ok() { printf '  %s[ok]%s        %s\n' "$C_OK" "$C_RST" "$*"; }
dep_required() { printf '  %s[REQUIRED]%s  %s\n' "$C_REQ" "$C_RST" "$*"; }
dep_optional() { printf '  %s[optional]%s  %s\n' "$C_OPT" "$C_RST" "$*"; }
dep_note() { printf '  %s%s%s\n' "$C_DIM" "$*" "$C_RST"; }
option() { printf '  %-18s %s\n' "$1" "$2"; }

os_family() {
    local version arch
    version=$(/usr/bin/sw_vers -productVersion 2>/dev/null || echo unknown)
    arch=$(/usr/bin/uname -m)
    case $arch in arm64) arch='Apple silicon' ;; x86_64) arch=Intel ;; esac
    echo "macOS $version ($arch)"
}

# deps MODE: audit (--missing-deps: report everything), build (build + runtime requirements),
# runtime (installing an existing build). Missing REQUIRED items return 1 and block the
# caller; OPTIONAL items never block.
deps() {
    local mode=${1:-audit} rv cv nv np os entry binary purpose
    local build_missing=0 runtime_missing=0 optional_missing=0 project_missing=0 node_via_nvm=0 node_missing=0 clt_missing=0
    printf '%sDependency check: BaradWatchU Client %s (%s)%s\n' "$C_BOLD" "$VERSION" "$(os_family)" "$C_RST"

    if [[ $mode != runtime ]]; then
        section 'Build requirements (required to compile)'
        # The tray companion (tray-icon, rfd) needs a newer toolchain than the agent alone.
        local rust_min=1.80.0; ((WITH_TRAY == 0)) || rust_min=1.92.0
        if command -v rustc >/dev/null && rv=$(rustc --version|awk '{print $2}') && ge "$rv" "$rust_min"; then dep_ok "rustc $rv"; else dep_required "rustc >= $rust_min$( ((WITH_TRAY)) && echo ' (tray companion; --without-tray needs 1.80)')"; build_missing=1; fi
        if command -v cargo >/dev/null && cv=$(cargo --version|awk '{print $2}') && ge "$cv" "$rust_min"; then dep_ok "cargo $cv"; else dep_required "cargo >= $rust_min"; build_missing=1; fi
        if command -v node >/dev/null && nv=$(node -p 'process.versions.node' 2>/dev/null) && [[ "$nv" == 20.* ]] && ge "$nv" 20.11.1; then
            dep_ok "Node.js $nv"
        elif select_node_from_nvm; then
            nv=$(node -p 'process.versions.node'); node_via_nvm=1
            dep_ok "Node.js $nv (selected from web/.nvmrc via nvm)"
        else
            node_missing=1 build_missing=1
            if load_nvm; then dep_required 'Node.js 20 >= 20.11.1: install it with (cd web && nvm install)'
            else dep_required 'Node.js 20 >= 20.11.1 (install Node 20 or nvm, then use web/.nvmrc)'; fi
        fi
        if command -v npm >/dev/null && np=$(npm --version) && ge "$np" 8.0.0; then dep_ok "npm $np"; else dep_required 'npm >= 8.0.0'; build_missing=1; fi
        # Xcode Command Line Tools: C compiler/linker for Rust crates (ring) and python3 for
        # the installer's asset validation. Probed without triggering the install dialog.
        if /usr/bin/xcode-select -p >/dev/null 2>&1 && [[ -x "$(/usr/bin/xcode-select -p)/usr/bin/clang" || -x /Library/Developer/CommandLineTools/usr/bin/clang ]]; then
            dep_ok "Xcode Command Line Tools ($(/usr/bin/xcode-select -p))"
        else
            dep_required 'Xcode Command Line Tools (C compiler, linker, python3)'; build_missing=1 clt_missing=1
        fi
        for entry in make tar /usr/bin/sips /usr/bin/iconutil; do
            if command -v "$entry" >/dev/null; then dep_ok "$entry"; else dep_required "build tool: $entry"; build_missing=1; fi
        done
        if [[ -x "$ROOT/web/node_modules/.bin/ng" && -d "$ROOT/web/node_modules/@angular-devkit/build-angular" ]]; then
            dep_ok 'Angular builder packages (web/node_modules)'
        else
            project_missing=1
            dep_note 'Angular builder packages are not in web/node_modules: the build installs them in its private cache with npm ci.'
        fi
    fi

    section 'Runtime requirements (required by the agent, its checks and this installer)'
    os=$(/usr/bin/sw_vers -productVersion 2>/dev/null || echo 0)
    if ge "$os" "$MACOS_MIN"; then dep_ok "macOS $os (>= $MACOS_MIN)"; else dep_required "macOS >= $MACOS_MIN (this Mac runs $os)"; runtime_missing=1; fi
    for entry in /bin/bash /usr/bin/plutil /usr/bin/awk /usr/bin/sed /usr/bin/grep /usr/bin/shasum /usr/bin/stat /bin/date /bin/ps /bin/launchctl; do
        if [[ -x $entry ]]; then dep_ok "$entry"; else dep_required "$entry (part of macOS)"; runtime_missing=1; fi
    done
    if /usr/bin/xcode-select -p >/dev/null 2>&1 && /usr/bin/python3 -c 'import sys' >/dev/null 2>&1; then
        dep_ok 'python3 (Xcode Command Line Tools; installer validation only)'
    else
        dep_required 'python3 from the Xcode Command Line Tools (installer validation only): xcode-select --install'; runtime_missing=1 clt_missing=1
    fi

    if ((WITH_TRAY)); then
        section 'Tray companion (optional: the tray and notifications work without these)'
        dep_note 'Runs in the menu bar of the logged-in user; the consent window and notifications use native macOS dialogs.'
        dep_note 'macOS asks once whether the tray may send notifications (System Settings > Notifications).'
    fi

    section 'Audit tools (part of macOS unless noted; a missing tool makes its check report WARN)'
    local -a runtime_tools=(
        '/usr/sbin/softwareupdate|REQ-001 Apple updates'
        '/usr/bin/xprotect|REQ-002 XProtect status (macOS 15+; older releases use the bundle version)'
        '/usr/bin/csrutil|REQ-002/009 System Integrity Protection'
        '/usr/sbin/spctl|REQ-002 Gatekeeper'
        '/usr/bin/codesign|REQ-002 Bitdefender signature'
        '/usr/bin/systemextensionsctl|REQ-002 Bitdefender network extension'
        '/usr/libexec/ApplicationFirewall/socketfilterfw|REQ-003 Application Firewall'
        '/usr/sbin/scutil|REQ-004/005 DNS and VPN configurations'
        '/usr/bin/fdesetup|REQ-006 FileVault'
        '/usr/bin/pmset|REQ-007 display sleep'
        '/usr/sbin/sysadminctl|REQ-007 password after sleep'
        '/usr/bin/pwpolicy|REQ-008 password policies'
        '/usr/bin/dscl|REQ-008 local accounts'
        '/usr/sbin/system_profiler|REQ-009 Secure Boot policy'
        '/usr/bin/open|dashboard opens the browser'
    )
    for entry in "${runtime_tools[@]}"; do
        IFS='|' read -r binary purpose <<< "$entry"
        if [[ -x $binary ]]; then dep_ok "$binary ${C_DIM}— $purpose${C_RST}"
        else dep_optional "$binary — $purpose"; optional_missing=$((optional_missing + 1)); fi
    done
    local -a vendor_tools=(
        '/Library/Bitdefender/AVP/product/bin/BDLDaemon.app|REQ-002 Bitdefender GravityZone (alternative: XProtect)'
        '/Applications/CatoClient.app|REQ-005 Cato VPN (alternative: WireGuard)'
        '/Applications/WireGuard.app|REQ-005 WireGuard VPN (alternative: Cato)'
    )
    for entry in "${vendor_tools[@]}"; do
        IFS='|' read -r binary purpose <<< "$entry"
        if [[ -e $binary ]]; then dep_ok "$binary ${C_DIM}— $purpose${C_RST}"; else dep_note "  -         $binary — $purpose: not installed"; fi
    done
    if [[ -x /opt/homebrew/sbin/dnsmasq || -x /usr/local/sbin/dnsmasq || -x /opt/local/sbin/dnsmasq ]]; then dep_ok "dnsmasq ${C_DIM}— REQ-004 method B${C_RST}"
    else dep_note '  -         dnsmasq — REQ-004 method B (method A is a HaGeZi blocklist in /etc/hosts): not installed'; fi

    section 'Summary'
    if ((build_missing || runtime_missing)); then
        printf '  %sRequired dependencies are missing: installation is blocked.%s\n' "$C_REQ" "$C_RST"
        ((clt_missing == 0)) || echo '  Command Line Tools: xcode-select --install'
        if ((build_missing)); then echo '  Rust:          https://rustup.rs (rustup toolchain install stable)'; fi
        if ((node_missing)) && ((node_via_nvm == 0)); then echo '  Node.js:       select Node.js 20 >= 20.11.1 using web/.nvmrc (with nvm: cd web && nvm install)'; fi
    else
        printf '  %sAll required dependencies are present.%s\n' "$C_OK" "$C_RST"
    fi
    if ((optional_missing)); then
        printf '  %s%s optional audit tool(s) missing%s: the related checks report WARN.\n' "$C_OPT" "$optional_missing" "$C_RST"
    fi
    ((node_via_nvm == 0)) || echo "  Using nvm Node.js $nv and its matching npm for this build."
    if ((project_missing)) && [[ $mode == build ]]; then echo '  Angular packages will be installed in the build cache; a --no-build install does not need them.'; fi
    if ((project_missing)) && [[ $mode == audit ]]; then echo "  Optional:      (cd '$ROOT/web' && npm ci --no-audit --no-fund) prepares a local development build"; fi
    echo
    ((build_missing == 0 && runtime_missing == 0))
}

# --- running instances (modelled on install.sh) --------------------------------
# A running agent or tray of THIS installation is identified by the exact executable path
# reported by the kernel (ps comm), never by name. This user's instances get SIGTERM and up to
# STOP_TIMEOUT seconds; nothing is SIGKILLed; other users' instances are reported.
STOP_TIMEOUT=${BARADWATCHU_STOP_TIMEOUT:-10}
[[ $STOP_TIMEOUT =~ ^[1-9][0-9]?$ ]] || { echo 'BARADWATCHU_STOP_TIMEOUT must be 1-99 seconds' >&2; exit 2; }
if [[ $EUID -eq 0 && -n ${SUDO_USER:-} && ${SUDO_USER} != root ]]; then REAL_UID=$(id -u -- "$SUDO_USER"); else REAL_UID=$EUID; fi
process_start() { # start time tells a process apart from a reused PID
    local start
    start=$(/bin/ps -o lstart= -p "$1" 2>/dev/null) || return 1
    [[ -n ${start// /} ]] || return 1
    printf '%s\n' "$start"
}
running_instances() { # "PID UID" for each process running $PREFIX/bin/$BIN or the tray
    local pid uid exe
    while read -r pid uid exe; do
        [[ $exe == "$PREFIX/bin/$BIN" || $exe == "$PREFIX/bin/$TRAY_BIN" ]] || continue
        printf '%s %s\n' "$pid" "$uid"
    done < <(/bin/ps -axww -o pid=,uid=,comm= 2>/dev/null)
}
service_pid() { # PID of the running LaunchDaemon, empty when absent or stopped
    { /bin/launchctl print "system/$SERVICE_LABEL" 2>/dev/null || true; } | sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\)$/\1/p' | head -n 1
}
describe_instances() {
    local pid uid found=0 will='will be' daemon_pid=''
    ((DRY)) && will='would be'
    if [[ $SERVICE_CURRENT == "$PREFIX/bin/$BIN" ]]; then daemon_pid=$(service_pid); fi
    while read -r pid uid; do
        found=1
        if [[ $pid == "$daemon_pid" ]]; then
            if [[ $SERVICE_ACTION == none ]]; then option 'running' "PID $pid, system service of this installation (left running)"
            else option 'running' "PID $pid, system service: $will stopped through launchd before files change"; fi
        elif [[ $uid == "$REAL_UID" ]]; then option 'running' "PID $pid, $will closed (SIGTERM, up to ${STOP_TIMEOUT} s) before files change"
        else option 'running' "PID $pid of user $uid, left running (not yours)"; fi
    done < <(running_instances)
    ((found)) || option 'running' 'no instance of this installation'
}
stop_running_instances() {
    local -a pids=() starts=() others=() alive=()
    local pid uid i waited=0 daemon_pid
    daemon_pid=$(service_pid)
    while read -r pid uid; do
        [[ $pid != "$daemon_pid" ]] || continue
        if [[ $uid == "$REAL_UID" ]]; then pids+=("$pid"); starts+=("$(process_start "$pid" || true)"); else others+=("$pid"); fi
    done < <(running_instances)
    ((${#others[@]} == 0)) || echo "Warning: BaradWatchU of this installation is also running for other users (PID ${others[*]}); it is not stopped and keeps the old files open until restarted." >&2
    ((${#pids[@]})) || return 0
    echo "Closing running BaradWatchU processes of this installation (PID ${pids[*]}) ..."
    for i in "${!pids[@]}"; do kill -TERM "${pids[$i]}" 2>/dev/null || true; done
    while :; do
        alive=()
        for i in "${!pids[@]}"; do
            [[ -n ${starts[$i]} && "$(process_start "${pids[$i]}" 2>/dev/null || true)" == "${starts[$i]}" ]] && alive+=("${pids[$i]}")
        done
        ((${#alive[@]})) || break
        ((waited < STOP_TIMEOUT * 10)) || fail "BaradWatchU process (PID ${alive[*]}) did not exit within ${STOP_TIMEOUT} s after SIGTERM; nothing was changed. Close it (Ctrl+C in its terminal, or Close tray) and run the installer again."
        sleep 0.1; waited=$((waited + 1))
    done
    echo "Closed. Start the dashboard again with: $BIN dashboard; the tray with: $TRAY_BIN"
}
print_options() { # every run starts with the effective plan
    local action=install privileges=none
    ((UNINSTALL)) && action=uninstall
    ((BUILD_ONLY)) && action='build only'
    ((MISSING)) && action='dependency check'
    prefix_writable || privileges='sudo, only for copying/removing files and the system service'
    printf '%sBaradWatchU Client %s installer (macOS)%s\n' "$C_BOLD" "$VERSION" "$C_RST"
    option 'action' "$action$( ((DRY)) && echo ' (dry run: nothing changes)')"
    if ((MISSING == 0)); then
        if ((BUILD_ONLY)); then :
        elif ((SYSTEM_INSTALL)); then option 'mode' "system installation ($PREFIX): complete Client with the system service for remote requests"
        else option 'mode' "per-user installation ($PREFIX): no system service, no remote communication; local audits, dashboard, tray, identity and reports work"; fi
        if ((UNINSTALL == 0)); then
            if ((NO_BUILD)); then option 'build' "reuse $BUILD_DIR (--no-build)"; else option 'build' "compile in $BUILD_DIR (macOS >= $MACOS_MIN, $(/usr/bin/uname -m))"; fi
        fi
        option 'binary' "$PREFIX/bin/$BIN"
        if ((UNINSTALL)); then option 'tray' "removed if installed; your LaunchAgent $TRAY_LABEL is removed when it starts $PREFIX/bin/$TRAY_BIN"
        elif ((WITH_TRAY)); then option 'tray' "$PREFIX/bin/$TRAY_BIN; start at login: $(if ((TRAY_AUTOSTART)); then echo 'enabled for the invoking user'; elif ((NO_TRAY_AUTOSTART)); then echo 'not enabled; a reinstall keeps the current choice'; else echo 'enabled on first install for the invoking user; a reinstall keeps the current choice'; fi)"
        else option 'tray' 'not installed (--without-tray)'; fi
        if ((UNINSTALL)); then option 'app' "$APP_ROOT removed when it belongs to this installation"
        else option 'app' "$APP_ROOT (Launchpad/Spotlight: starts the tray, opens the dashboard)"; fi
        option 'manifest' "$manifest"
        ((BUILD_ONLY)) || option 'service' "$SERVICE_NOTE"
        ((BUILD_ONLY)) || option 'privileges' "$privileges"
        option 'user data' "kept: ~/.config/baradwatchu (settings, custom-checks, identity, trust store), ~/.local/state/baradwatchu (events, consent) and ~/.cache/baradwatchu/audit (audit history), or the XDG_* folders when set; no key is generated and no Server connection is started"
        ((BUILD_ONLY)) || describe_instances
    fi
    option 'system' "$(os_family)"
    echo
}

# realpath -m equivalent: lexical normalisation, then the longest existing prefix resolved.
canonical() {
    local path=$1 part existing rest='' result=''
    local -a parts=() out=()
    [[ $path == /* ]] || path="$PWD/$path"
    IFS='/' read -r -a parts <<< "$path"
    for part in ${parts[@]+"${parts[@]}"}; do
        case $part in
            ''|.) ;;
            ..) ((${#out[@]} == 0)) || unset "out[$((${#out[@]} - 1))]" ;;
            *) out+=("$part") ;;
        esac
    done
    for part in ${out[@]+"${out[@]}"}; do result+="/$part"; done
    result=${result:-/}
    existing=$result
    while [[ ! -e $existing && $existing != / ]]; do
        rest="/${existing##*/}$rest"
        existing=$(dirname -- "$existing")
    done
    if [[ -d $existing ]]; then existing=$(cd -P -- "$existing" && pwd -P); fi
    [[ $existing == / ]] && existing=''
    printf '%s\n' "${existing}${rest:-}" | sed 's|^$|/|'
}
prefix_writable() { local p="$PREFIX"; (( EUID == 0 )) && return 0; while [[ ! -e "$p" ]]; do p=$(dirname -- "$p"); done; [[ -d "$p" && -w "$p" && -x "$p" ]]; }
authenticate_sudo() {
    local answer
    while ! sudo -v; do
        [[ -t 0 ]] || return 1
        read -r -p 'Retry using sudo? [y/N] ' answer || answer=''
        [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]] || return 1
    done
}
fingerprint() {
    (cd "$ROOT"; local paths=(Cargo.toml install-macos.sh crates catalog web); [[ ! -f Cargo.lock ]] || paths+=(Cargo.lock); [[ ! -d .cargo ]] || paths+=(.cargo); find "${paths[@]}" -type d \( -name .git -o -name target -o -name node_modules -o -name dist -o -name .angular -o -name out-tsc \) -prune -o \( -type f -o -type l \) -print0 | LC_ALL=C sort -z | xargs -0 /usr/bin/shasum -a 256 | /usr/bin/shasum -a 256 | awk '{print $1}')
}
web_ok() {
    local pv av lv
    pv=$(awk -F '"' '/^[[:space:]]*"version":[[:space:]]*"/ {print $4;exit}' "$ROOT/web/package.json")
    av=$(sed -n "s/^export const APP_VERSION = '\([^']*\)';$/\1/p" "$ROOT/web/src/app-version.ts")
    lv=$(awk -F '"' '/^[[:space:]]*"version":[[:space:]]*"/ {print $4;exit}' "$ROOT/web/package-lock.json")
    [[ "$pv" == "$VERSION" && "$av" == "$VERSION" && "$lv" == "$VERSION" ]]
}
mvget() { sed -n "s/^$1=//p" "$2"|head -1; }
artifact_fingerprint() {
    (cd "$BUILD_DIR"; { printf '%s\0' "cargo-target/release/$BIN"; [[ ! -f "cargo-target/release/$TRAY_BIN" ]] || printf '%s\0' "cargo-target/release/$TRAY_BIN"; find cargo-target/share/baradwatchu-client angular/browser app -type f -print0; } | LC_ALL=C sort -z | xargs -0 /usr/bin/shasum -a 256 | /usr/bin/shasum -a 256 | awk '{print $1}')
}
validate_build() {
    local m="$BUILD_DIR/.baradwatchu-build" platform os
    platform="$(uname -s)-$(uname -m)"
    [[ -f "$m" && ! -L "$m" && $(sed -n '1p' "$m") == 'BaradWatchU build marker v2' ]] || fail "no current build cache at $BUILD_DIR; rebuild with --build-only"
    [[ $(mvget product "$m") == client && $(mvget source "$m") == "$ROOT" ]] || fail 'build cache source/product mismatch'
    [[ $(mvget state "$m") == complete ]] || fail 'build cache is incomplete'
    [[ $(mvget platform "$m") == "$platform" && $(mvget version "$m") == "$VERSION" ]] || fail 'build cache platform/version mismatch'
    os=$(/usr/bin/sw_vers -productVersion 2>/dev/null || echo 0)
    [[ $(mvget macos "$m") =~ ^[0-9]+\.[0-9]+$ ]] || fail 'build cache has no macOS deployment metadata; rebuild on this Mac'
    ge "$os" "$(mvget macos "$m")" || fail "build cache requires macOS $(mvget macos "$m") or later"
    web_ok || fail 'Angular version metadata mismatch; run node web/sync-version.mjs and rebuild'
    [[ $(mvget fingerprint "$m") == "$(fingerprint)" ]] || fail 'build cache is stale for current sources'
    [[ -x "$BUILD_DIR/cargo-target/release/$BIN" && ! -L "$BUILD_DIR/cargo-target/release/$BIN" ]] || fail 'release executable missing or unsafe'
    if ((WITH_TRAY)); then
        [[ $(mvget tray "$m") == 1 && -x "$BUILD_DIR/cargo-target/release/$TRAY_BIN" && ! -L "$BUILD_DIR/cargo-target/release/$TRAY_BIN" ]] || fail 'build cache has no tray companion; rebuild, or install with --without-tray'
    fi
    validate_requirement_assets "$BUILD_DIR/cargo-target" || fail 'cached check folders or trusted builtin hashes are incomplete or unsafe; rebuild'
    [[ -s "$BUILD_DIR/angular/browser/index.html" ]] || fail 'Angular assets incomplete'
    [[ -s "$BUILD_DIR/app/AppIcon.icns" && ! -L "$BUILD_DIR/app" && ! -L "$BUILD_DIR/app/AppIcon.icns" ]] || fail 'application icon missing; rebuild with --build-only'
    [[ -n "$(find "$BUILD_DIR/angular/browser" -type f -name '*.js' -print -quit)" ]] || fail 'Angular JavaScript bundle missing'
    [[ ! -L "$BUILD_DIR/angular" && ! -L "$BUILD_DIR/angular/browser" && -z "$(find "$BUILD_DIR/angular/browser" -type l -print -quit)" ]] || fail 'symlinks are not allowed in built web assets'
    [[ $(mvget artifacts "$m") == "$(artifact_fingerprint)" ]] || fail 'cached artifacts changed; rebuild with --build-only'
    echo "Validated build $BUILD_DIR ($platform, $VERSION, macOS >= $(mvget macos "$m"))"
}
validate_requirement_assets() {
    # The trusted manifest lists every file of every built-in check folder (one line per file).
    # Each macOS file must be installed with that hash, nothing unlisted may sit in the check
    # folders, and every check configuration must reference only listed files.
    /usr/bin/python3 -I -c '
import hashlib, json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
base = "share/baradwatchu-client/"
checks_relative = base + "catalog/checks-macos"
try:
    def safe_file(relative, executable=False):
        parts = pathlib.Path(relative).parts
        if any((root / pathlib.Path(*parts[:index])).is_symlink() for index in range(1, len(parts) + 1)):
            return False
        path = root / relative
        return path.is_file() and (not executable or os.access(path, os.X_OK))
    def safe_relative(value):
        path = pathlib.PurePosixPath(value)
        return bool(value) and not path.is_absolute() and all(part not in ("..", "") for part in path.parts)
    checks_dir = root / checks_relative
    if checks_dir.is_symlink() or not checks_dir.is_dir():
        raise ValueError("check folders missing or symlink")
    for other in ("checks", "checks-windows"):
        if (root / base / "catalog" / other).exists():
            raise ValueError("check folders of another platform are staged")
    if (root / "share/baradwatchu-client/tools").exists() or (root / "share/baradwatchu-client/tools").is_symlink():
        raise ValueError("obsolete duplicated tools tree remains in staged runtime")
    digest_path = root / "share/baradwatchu-client/catalog/builtin-tools.sha256"
    if not safe_file("share/baradwatchu-client/catalog/builtin-tools.sha256"):
        raise ValueError("builtin hash manifest missing or symlink")
    entries, ids = {}, set()
    for line in digest_path.read_text(encoding="ascii").splitlines():
        ident, platform, path, digest = line.split()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid builtin hash entry")
        if platform != "macos":
            continue
        if not path.startswith(f"catalog/checks-macos/{ident}/") or not safe_relative(path) or path in entries:
            raise ValueError("invalid builtin hash path")
        entries[path] = digest
        ids.add(ident)
    for path, digest in entries.items():
        if not safe_file(base + path, executable=path.endswith(".sh")):
            raise ValueError("builtin check file missing, non-executable, or symlink")
        if hashlib.sha256((root / base / path).read_bytes()).hexdigest() != digest:
            raise ValueError("builtin hash manifest mismatch")
    installed = set()
    for path in checks_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in check folders")
        if path.is_file():
            installed.add(path.relative_to(root / base).as_posix())
    if installed != set(entries):
        raise ValueError("check folders contain unlisted files or miss listed ones")
    discovered = set()
    for folder in checks_dir.iterdir():
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError("unsafe check folder")
        ident = folder.name
        prefix = f"catalog/checks-macos/{ident}/"
        config = json.loads((folder / "configuration.json").read_text(encoding="utf-8"))
        if config.get("id") != ident or config.get("schemaVersion") != "baradwatchu.custom-checks.v1":
            raise ValueError("invalid check configuration identity")
        tool_path = config.get("toolPath")
        providers = config.get("providers") or {}
        if tool_path and not providers:
            tool = str(pathlib.PurePosixPath(prefix) / tool_path)
            if not safe_relative(tool_path) or entries.get(tool) != config.get("expectedSha256"):
                raise ValueError("builtin tool hash manifest mismatch")
        elif providers and not tool_path and "expectedSha256" not in config:
            for provider in providers.values():
                tool = str(pathlib.PurePosixPath(prefix) / provider["toolPath"])
                if not safe_relative(provider["toolPath"]) or tool not in entries:
                    raise ValueError("provider tool not in builtin hash manifest")
        else:
            raise ValueError("check configuration needs toolPath or providers")
        discovered.add(ident)
    if not discovered or discovered != ids:
        raise ValueError("builtin hash manifest does not match discovered folders")
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
' "$1"
}
prepare_cache() {
    local m="$BUILD_DIR/.baradwatchu-build" found
    if [[ -e "$BUILD_DIR" ]]; then
        [[ -d "$BUILD_DIR" && ! -L "$BUILD_DIR" ]] || fail 'build dir must be a real directory'
        if [[ -e "$m" ]]; then
            [[ -f "$m" && ! -L "$m" && $(sed -n '1p' "$m") =~ ^BaradWatchU\ build\ marker\ v[12]$ ]] || fail 'unrecognized build marker'
            [[ $(mvget product "$m") == client && $(mvget source "$m") == "$ROOT" ]] || fail 'build dir is marked for another source/product'
        else
            found=$(find "$BUILD_DIR" -mindepth 1 -print -quit); [[ -z "$found" ]] || fail 'refusing non-empty, unmarked build directory'
        fi
    else mkdir -p -- "$BUILD_DIR"; fi
    printf 'BaradWatchU build marker v2\nproduct=client\nsource=%s\nstate=incomplete\n' "$ROOT" > "$m"
}
# Application icon from the report brand mark, with the macOS tools sips and iconutil.
make_app_icon() {
    local source="$ROOT/crates/agent/assets/report-brand-mark.png" set="$BUILD_DIR/app/AppIcon.iconset" size
    [[ -f $source && ! -L $source ]] || fail "missing $source"
    if [[ -e "$BUILD_DIR/app" ]]; then [[ -d "$BUILD_DIR/app" && ! -L "$BUILD_DIR/app" ]] || fail 'unsafe app folder in build cache'; find "$BUILD_DIR/app" -depth -delete; fi
    mkdir -p -- "$set"
    for size in 16 32 128 256; do
        /usr/bin/sips -z "$size" "$size" "$source" --out "$set/icon_${size}x${size}.png" >/dev/null
        /usr/bin/sips -z "$((size * 2))" "$((size * 2))" "$source" --out "$set/icon_${size}x${size}@2x.png" >/dev/null
    done
    /usr/bin/iconutil -c icns "$set" -o "$BUILD_DIR/app/AppIcon.icns"
    find "$set" -depth -delete
}
build() {
    local source_before
    (( EUID != 0 )) || fail 'refusing to build as root; build as user, then install with --no-build'
    deps build || fail 'required dependencies are missing (see the [REQUIRED] items above); nothing was built or installed'
    [[ -f "$ROOT/Cargo.lock" && -f "$ROOT/web/package-lock.json" ]] || fail 'Cargo.lock and web/package-lock.json are required; resolve dependencies before building'
    web_ok || node "$ROOT/web/sync-version.mjs"
    source_before=$(fingerprint)
    prepare_cache
    export MACOSX_DEPLOYMENT_TARGET=$MACOS_MIN
    if ((WITH_TRAY)); then
        (cd "$ROOT" && CARGO_TARGET_DIR="$BUILD_DIR/cargo-target" cargo build --release --workspace --locked)
    else
        (cd "$ROOT" && CARGO_TARGET_DIR="$BUILD_DIR/cargo-target" cargo build --release -p baradwatchu-agent --locked)
        # A tray binary from an earlier build must not be installed or fingerprinted.
        rm -f -- "$BUILD_DIR/cargo-target/release/$TRAY_BIN"
    fi
    # npm ci removes node_modules: use a private workspace, never the checkout.
    WEB_BUILD_DIR=$(mktemp -d "$BUILD_DIR/web-source.XXXXXX")
    cp -- "$ROOT/Cargo.toml" "$WEB_BUILD_DIR/Cargo.toml"
    (cd "$ROOT" && tar --exclude=web/node_modules --exclude=web/dist --exclude=web/.angular --exclude=web/out-tsc -cf - web) | tar -C "$WEB_BUILD_DIR" -xf -
    (cd "$WEB_BUILD_DIR/web"; export npm_config_cache="${npm_config_cache:-$BUILD_DIR/npm-cache}" npm_config_devdir="$BUILD_DIR/node-gyp"; npm ci --no-audit --no-fund && npm run build -- --output-path="$BUILD_DIR/angular")
    make_app_icon
    [[ "$source_before" == "$(fingerprint)" ]] || fail 'sources changed during build; retry with a stable checkout'
    [[ -x "$BUILD_DIR/cargo-target/release/$BIN" && -s "$BUILD_DIR/angular/browser/index.html" && -n "$(find "$BUILD_DIR/angular/browser" -type f -name '*.js' -print -quit)" ]] || fail 'native build is incomplete; check Cargo target configuration'
    [[ $("$BUILD_DIR/cargo-target/release/$BIN" --version) == "BaradWatchU $PRODUCT $VERSION" ]] || fail 'built version mismatch'
    if ((WITH_TRAY)); then [[ $("$BUILD_DIR/cargo-target/release/$TRAY_BIN" --version) == "BaradWatchU Tray $VERSION" ]] || fail 'built tray version mismatch'; fi
    printf 'BaradWatchU build marker v2\nproduct=client\nsource=%s\nstate=complete\nplatform=%s\nversion=%s\nmacos=%s\nfingerprint=%s\ntray=%s\nartifacts=%s\n' "$ROOT" "$(uname -s)-$(uname -m)" "$VERSION" "$MACOS_MIN" "$source_before" "$WITH_TRAY" "$(artifact_fingerprint)" > "$BUILD_DIR/.baradwatchu-build"
    validate_build
}
owner() { # installer package (.pkg receipt) that owns a path, if any
    /usr/sbin/pkgutil --file-info "$1" 2>/dev/null | sed -n 's/^pkgid: //p' | head -n 1
    return 0
}
allowed() { [[ "$1" != /* && "$1" != *'..'* && ( "$1" == "bin/$BIN" || "$1" == "bin/$TRAY_BIN" || "$1" == share/baradwatchu-client/* ) ]]; }
# Per-user tray autostart (LaunchAgent). Runs unprivileged, as the invoking user, never as root.
user_autostart_file() { printf '%s/Library/LaunchAgents/%s.plist\n' "${HOME:-/nonexistent}" "$TRAY_LABEL"; }
remove_user_autostart() {
    local file; file=$(user_autostart_file)
    [[ -f "$file" && ! -L "$file" ]] || return 0
    [[ $(/usr/bin/plutil -extract Label raw -o - "$file" 2>/dev/null) == "$TRAY_LABEL" && $(/usr/bin/plutil -extract ProgramArguments.0 raw -o - "$file" 2>/dev/null) == "$PREFIX/bin/$TRAY_BIN" ]] || return 0
    if ((DRY)); then echo "Would remove tray LaunchAgent $file"; else unlink -- "$file"; echo "Removed tray LaunchAgent $file"; fi
}
post_install_user() {
    ((WITH_TRAY)) || return 0
    if ((TRAY_AUTOSTART || (FRESH && ! NO_TRAY_AUTOSTART))); then
        if ((EUID == 0)); then echo "Tray autostart not changed for root; as your user run: $PREFIX/bin/$TRAY_BIN autostart enable"
        else "$PREFIX/bin/$TRAY_BIN" autostart enable || echo 'Warning: tray autostart could not be enabled' >&2; fi
    elif ((EUID != 0)); then
        echo "$("$PREFIX/bin/$TRAY_BIN" autostart status 2>/dev/null || true) (unchanged; change it from the tray menu: Avvia al login)"
    fi
    echo "Tray companion: start it with $PREFIX/bin/$TRAY_BIN; closing it does not stop the agent."
}
# --- system service (packaging/service/install-service.sh does the work) ----------------
# Invariant: whenever $PREFIX/bin/$BIN is replaced or removed, a service running that file is
# stopped first and then either restarted on the new file (and checked) or removed.
plan_service() {
    local agent="$PREFIX/bin/$BIN" state='' path='' active=''
    SERVICE_ACTION=none SERVICE_CURRENT='' SERVICE_ACTIVE=0
    if [[ -x /bin/launchctl && -f "$SERVICE_SCRIPT" && ! -L "$SERVICE_SCRIPT" ]]; then
        read -r state path active < <(/bin/bash "$SERVICE_SCRIPT" --status) || true
        if [[ $state == installed ]]; then SERVICE_CURRENT=$path; [[ $active != active ]] || SERVICE_ACTIVE=1; fi
    fi
    if ((SYSTEM_INSTALL == 0)); then
        # Files belong to this user: a root service must never run them.
        [[ $SERVICE_CURRENT != "$agent" ]] || fail "the system service runs $agent but $PREFIX is writable without root; run the installer with sudo"
        SERVICE_NOTE='none (per-user installation; remote requests need the system installation)'
        return 0
    fi
    if ((UNINSTALL)); then
        if [[ $SERVICE_CURRENT == "$agent" ]]; then SERVICE_ACTION=remove SERVICE_NOTE="stopped and removed before the files (registrations in /Library/Application Support/BaradWatchU/service are kept)"
        elif [[ -n $SERVICE_CURRENT ]]; then SERVICE_NOTE="left unchanged: it runs $SERVICE_CURRENT, not this installation"
        else SERVICE_NOTE='not installed'; fi
        return 0
    fi
    [[ -x /bin/launchctl ]] || fail 'the system installation includes the system service and needs launchd (launchctl); for a per-user installation use --local'
    [[ -f "$SERVICE_SCRIPT" && ! -L "$SERVICE_SCRIPT" ]] || fail "missing $SERVICE_SCRIPT"
    # One system service per machine: never take over another installation's one silently.
    [[ -z $SERVICE_CURRENT || $SERVICE_CURRENT == "$agent" ]] || fail "the system service belongs to another BaradWatchU installation ($SERVICE_CURRENT); uninstall that installation first (or remove its service: sudo $SERVICE_SCRIPT --uninstall). Nothing was changed."
    SERVICE_ACTION=install
    if [[ -n $SERVICE_CURRENT ]]; then SERVICE_NOTE='updated: stopped before the files change, restarted on the new executable (checked)'
    else SERVICE_NOTE="installed: LaunchDaemon $SERVICE_LABEL (/Library/LaunchDaemons), root, started now and at boot"; fi
    SERVICE_NOTE+='; outbound Server connections start only when enabled by a registered user'
}
# Before files change: stop this installation's service so nothing keeps running the old file.
service_before_files() {
    [[ $SERVICE_ACTION != none && $SERVICE_CURRENT == "$PREFIX/bin/$BIN" ]] || return 0
    /bin/bash "$SERVICE_SCRIPT" --stop --agent="$PREFIX/bin/$BIN" || fail 'could not stop the system service; nothing was changed'
    SERVICE_STOPPED=1
}
service_after_files() {
    local agent="$PREFIX/bin/$BIN"
    case $SERVICE_ACTION in
        install)
            SERVICE_PHASE=1
            if ! /bin/bash "$SERVICE_SCRIPT" --agent="$agent"; then
                /bin/bash "$SERVICE_SCRIPT" --stop --agent="$agent" >/dev/null 2>&1 || true
                fail "BaradWatchU Client $VERSION files are installed, but the system service could not be installed or started (see above); it is stopped, so no old executable is running. Fix the cause, then run: $SELF --no-build --build-dir='$BUILD_DIR'"
            fi ;;
        remove)
            SERVICE_PHASE=1
            /bin/bash "$SERVICE_SCRIPT" --uninstall --agent="$agent" || fail "could not remove the system service; run: sudo $SERVICE_SCRIPT --uninstall" ;;
    esac
    SERVICE_STOPPED=0
}
# EXIT trap: the installation failed after stopping the service and before touching it again.
restore_service() {
    ((SERVICE_STOPPED && ! SERVICE_PHASE && SERVICE_ACTIVE)) || return 0
    SERVICE_STOPPED=0
    echo "Installation interrupted: restarting the system service on the files in place ..." >&2
    /bin/bash "$SERVICE_SCRIPT" --start --agent="$PREFIX/bin/$BIN" >&2 || echo "Warning: the system service is stopped; start it with: sudo launchctl bootstrap system /Library/LaunchDaemons/$SERVICE_LABEL.plist" >&2
}
manifest="$PREFIX/share/baradwatchu-source/$BIN.manifest"
MANIFEST_KIND=client-macos
# Previous manifest entries: parallel arrays (bash 3.2 has no associative arrays).
OLD_RELS=() OLD_HASHES=() OLD_DONE=()
load_manifest() {
    local line k h p
    [[ -f "$manifest" && ! -L "$manifest" && $(sed -n '1p' "$manifest") == 'BaradWatchU source manifest v1' && $(sed -n '2p' "$manifest") == "$MANIFEST_KIND" && $(sed -n '3p' "$manifest") == "$PREFIX" ]] || fail 'source manifest missing, unsafe or mismatched'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS=$'\t' read -r k h p <<< "$line"
        case $k in
            file) [[ "$h" =~ ^[a-f0-9]{64}$ ]] && allowed "$p" || fail 'invalid manifest ownership entry' ;;
            app) [[ "$h" =~ ^[a-f0-9]{64}$ ]] && app_allowed "$p" || fail 'invalid manifest application entry' ;;
            approot) [[ "$h" == - ]] && app_root_allowed "$p" || fail 'invalid manifest application location' ;;
            *) fail 'invalid manifest ownership entry' ;;
        esac
    done < <(tail -n +5 "$manifest")
}
old_index() { # REL -> index in OLD_RELS, or failure
    local i
    for i in "${!OLD_RELS[@]}"; do [[ ${OLD_RELS[$i]} == "$1" ]] && { printf '%s\n' "$i"; return 0; }; done
    return 1
}
hash_ok() { [[ -f "$1" && ! -L "$1" && $(sha256 "$1") == "$2" ]]; }
# --- application bundle (Launchpad/Spotlight entry) -------------------------------------
# System installation: /Applications/BaradWatchU.app; per user: ~/Applications/BaradWatchU.app.
# Its files are manifest entries "app" (paths inside the bundle) under one "approot" entry.
APP_NAME=BaradWatchU.app
app_location() { if ((SYSTEM_INSTALL)); then printf '/Applications/%s\n' "$APP_NAME"; else printf '%s/Applications/%s\n' "${HOME:-/nonexistent}" "$APP_NAME"; fi; }
app_allowed() { [[ $1 == Contents/Info.plist || $1 == Contents/MacOS/BaradWatchU || $1 == Contents/Resources/AppIcon.icns ]]; }
app_root_allowed() { [[ $1 == "/Applications/$APP_NAME" || $1 == "${HOME:-/nonexistent}/Applications/$APP_NAME" ]]; }
# The folders that hold the bundle must be real directories (no symlink redirection).
app_parent_ok() {
    local path=$1
    while [[ $path != / ]]; do
        [[ ! -L $path ]] || fail "symlink in application path: $path"
        [[ ! -e $path || -d $path ]] || fail "non-directory application path: $path"
        path=$(dirname -- "$path")
    done
}
# Entries of an existing manifest: kind, hash, path (one per line, tab-separated).
manifest_entries() { if [[ -f "$manifest" ]]; then tail -n +5 "$manifest"; fi; }
old_app_root() { manifest_entries | awk -F'\t' '$1 == "approot" { print $3; exit }'; }
# Stage the bundle in STAGE_DIR/app: launcher script, Info.plist, icon.
stage_app() {
    local contents="$STAGE_DIR/app/Contents" bin
    mkdir -p "$contents/MacOS" "$contents/Resources"
    bin=$(printf '%q' "$PREFIX/bin")
    cat > "$contents/MacOS/BaradWatchU" <<EOF
#!/bin/bash
# BaradWatchU launcher (installed by install-macos.sh for $PREFIX): starts the tray when it is
# not running (single instance per user) and opens the local dashboard in the browser.
BIN=$bin
if [ -x "\$BIN/$TRAY_BIN" ]; then /usr/bin/nohup "\$BIN/$TRAY_BIN" >/dev/null 2>&1 & fi
/usr/bin/nohup "\$BIN/$BIN" dashboard >/dev/null 2>&1 &
exit 0
EOF
    chmod 0755 "$contents/MacOS/BaradWatchU"
    cat > "$contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>BaradWatchU</string>
  <key>CFBundleExecutable</key><string>BaradWatchU</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleIdentifier</key><string>io.baradwatchu.client</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>BaradWatchU</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>LSMinimumSystemVersion</key><string>$MACOS_MIN</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
    /usr/bin/plutil -lint "$contents/Info.plist" >/dev/null || fail 'invalid application Info.plist'
    install -m 0644 "$BUILD_DIR/app/AppIcon.icns" "$contents/Resources/AppIcon.icns"
}
# Before any change: the bundle may only replace files this installation owns, unchanged.
check_app() {
    local root=$1 old_root k h rel dest
    old_root=$(old_app_root)
    app_parent_ok "$(dirname -- "$root")"
    if [[ -e $root || -L $root ]]; then
        [[ -d $root && ! -L $root ]] || fail "$root exists and is not an application folder"
        [[ $old_root == "$root" ]] || fail "$root belongs to another BaradWatchU installation or was not created by this installer; remove it or uninstall that installation first. Nothing was changed."
    fi
    [[ -n $old_root ]] || return 0
    while IFS=$'\t' read -r k h rel; do
        [[ $k == app ]] || continue
        dest="$old_root/$rel"
        if [[ -e $dest || -L $dest ]]; then hash_ok "$dest" "$h" || fail "changed file preserved: $dest"; fi
    done < <(manifest_entries)
}
# Remove the files of the recorded bundle (already checked) and its empty folders.
remove_app() {
    local root=$1 k h rel
    [[ -n $root ]] || return 0
    while IFS=$'\t' read -r k h rel; do
        [[ $k == app ]] || continue
        if [[ -e "$root/$rel" ]]; then if ((DRY)); then echo "Would remove $root/$rel"; else unlink -- "$root/$rel"; fi; fi
    done < <(manifest_entries)
    ((DRY)) && return 0
    rmdir -- "$root/Contents/MacOS" "$root/Contents/Resources" "$root/Contents" "$root" 2>/dev/null || true
}
# Copy the staged bundle (files replaced atomically) and append its manifest entries.
install_app() {
    local root=$1 path rel dest tmp h
    mkdir -p -- "$root/Contents/MacOS" "$root/Contents/Resources"
    printf 'approot\t-\t%s\n' "$root" >> "$STAGE_DIR/manifest-entries"
    while IFS= read -r -d '' path; do
        rel=${path#"$STAGE_DIR/app"/}; app_allowed "$rel" || fail "staged application path not allowed: $rel"
        dest="$root/$rel"; tmp=$(mktemp "${dest}.baradwatchu.XXXXXX")
        if ! install -m 0644 "$path" "$tmp"; then unlink -- "$tmp"; fail "could not stage application file: $dest"; fi
        [[ $rel != Contents/MacOS/BaradWatchU ]] || chmod 0755 "$tmp"
        if ! mv -f -- "$tmp" "$dest"; then unlink -- "$tmp"; fail "could not replace application file: $dest"; fi
        h=$(sha256 "$path"); printf 'app\t%s\t%s\n' "$h" "$rel" >> "$STAGE_DIR/manifest-entries"
    done < <(find "$STAGE_DIR/app" -type f -print0)
    /usr/bin/touch "$root"   # let Launchpad/Spotlight notice the updated bundle
}
# Same deployment boundary as runtime: root or installing user, no writable
# group/other ancestors except trusted sticky directories such as /tmp.
safe_parent() {
    local path=$1 uid mode root_uid
    root_uid=$(stat -f %u /)
    while [[ "$path" != / ]]; do
        [[ ! -L "$path" ]] || fail "symlink in installation path: $path"
        if [[ -e "$path" ]]; then
            [[ -d "$path" ]] || fail "non-directory installation parent: $path"
            uid=$(stat -f %u -- "$path"); mode=$(stat -f '%Mp%Lp' -- "$path")   # %Mp: sticky/setuid bits, like GNU %a
            [[ "$uid" == "$EUID" || "$uid" == "$root_uid" ]] || fail "untrusted installation directory owner: $path"
            (( (8#$mode & 0022) == 0 || (8#$mode & 01000) != 0 )) || fail "writable group/other installation directory: $path"
        fi
        path=$(dirname -- "$path")
    done
}
uninstall() {
    local line k h p path o parent manifest_parent count=0 app_root
    manifest_parent=$(canonical "$(dirname -- "$manifest")"); [[ "$manifest_parent" == "$PREFIX"/* ]] || fail 'manifest path escapes prefix'
    o=$(owner "$manifest"); [[ -z "$o" ]] || fail "installer package owns source manifest ($o)"
    load_manifest
    # Preflight every owned path before removing any of them, so a modified
    # later entry cannot cause a partially completed uninstall.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue; IFS=$'\t' read -r k h p <<< "$line"; [[ $k == file ]] || continue; path="$PREFIX/$p"
        parent=$(canonical "$(dirname -- "$path")"); [[ "$parent" == "$PREFIX"/* ]] || fail "manifest path escapes prefix: $path"
        o=$(owner "$path"); [[ -z "$o" ]] || fail "installer package owns $path ($o)"
        if [[ -e "$path" || -L "$path" ]]; then hash_ok "$path" "$h" || fail "changed file preserved: $path"; fi
    done < <(tail -n +5 "$manifest")
    app_root=$(old_app_root)
    [[ -z $app_root ]] || check_app "$app_root"
    if ((DRY)); then
        [[ $SERVICE_ACTION != remove ]] || echo "Would stop and remove the system service of $PREFIX/bin/$BIN"
    else
        service_before_files; stop_running_instances; service_after_files
    fi
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue; IFS=$'\t' read -r k h p <<< "$line"; [[ $k == file ]] || continue; path="$PREFIX/$p"
        parent=$(canonical "$(dirname -- "$path")"); [[ "$parent" == "$PREFIX"/* ]] || fail "manifest path escapes prefix: $path"
        o=$(owner "$path"); [[ -z "$o" ]] || fail "installer package owns $path ($o)"
        if [[ -e "$path" || -L "$path" ]]; then hash_ok "$path" "$h" || fail "changed file preserved: $path"; if ((DRY)); then echo "Would remove $path"; else unlink -- "$path"; fi; count=$((count + 1)); fi
    done < <(tail -n +5 "$manifest")
    remove_app "$app_root"
    if [[ -n $app_root ]]; then if ((DRY)); then echo "Would remove the application $app_root"; else echo "Application $app_root removed."; fi; fi
    if ((DRY)); then echo "Would remove $manifest"; else unlink -- "$manifest"; echo 'Manifest removed; configuration, identities, trust stores, history and service registrations preserved.'; fi
    echo "Uninstall complete; $count files processed. Empty directories remain."
}
install_source() {
    local app=share/baradwatchu-client/web path rel dest parent o h line tmp i k manifest_parent manifest_owner index present app_root old_root
    local -a files=() rels=()
    [[ ! -e "$PREFIX" || -d "$PREFIX" ]] || fail 'prefix exists and is not a directory'
    # Decided before any change (and before a sudo re-exec): no manifest = first installation.
    if [[ -e "$manifest" || -L "$manifest" ]]; then FRESH=0; else FRESH=1; fi
    if ((NO_BUILD)); then
        ((REEXEC)) || deps runtime || fail 'required runtime dependencies are missing (see the [REQUIRED] items above); nothing was installed'
        validate_build
    else build; fi
    if ! prefix_writable; then
        command -v sudo >/dev/null || fail "writing to $PREFIX needs root privileges and sudo is unavailable; run as root with --no-build --build-dir='$BUILD_DIR' or use --local"
        if ! authenticate_sudo; then fail "sudo authentication failed; the validated build is kept at $BUILD_DIR; rerun with --no-build --build-dir='$BUILD_DIR' after sudo works"; fi
        echo "Root privileges are needed to write to $PREFIX; sudo will be used for file installation only."
        # Not exec: per-user steps (tray autostart) run afterwards as the invoking user.
        local -a reexec=(--no-build --build-dir="$BUILD_DIR" --prefix="$PREFIX" --reexec)
        ((WITH_TRAY)) || reexec+=(--without-tray)
        sudo /bin/bash "$SELF" "${reexec[@]}" || exit $?
        post_install_user
        exit 0
    fi
    safe_parent "$PREFIX"
    STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/baradwatchu-client-stage.XXXXXX")
    mkdir -p "$STAGE_DIR/bin"
    install -m 0755 "$BUILD_DIR/cargo-target/release/$BIN" "$STAGE_DIR/bin/$BIN"
    if ((WITH_TRAY)); then
        install -m 0755 "$BUILD_DIR/cargo-target/release/$TRAY_BIN" "$STAGE_DIR/bin/$TRAY_BIN"
    fi
    mkdir -p "$STAGE_DIR/share/baradwatchu-client"
    cp -a "$BUILD_DIR/cargo-target/share/baradwatchu-client/." "$STAGE_DIR/share/baradwatchu-client/"
    mkdir -p "$STAGE_DIR/$app"; cp -a "$BUILD_DIR/angular/browser/." "$STAGE_DIR/$app/"
    stage_app
    : > "$STAGE_DIR/manifest-entries"
    if [[ -e "$manifest" || -L "$manifest" ]]; then
        load_manifest
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            IFS=$'\t' read -r k h rel <<< "$line"
            [[ $k == file ]] || continue
            OLD_RELS+=("$rel"); OLD_HASHES+=("$h"); OLD_DONE+=(0)
        done < <(tail -n +5 "$manifest")
    fi
    while IFS= read -r -d '' path; do
        rel=${path#"$STAGE_DIR"/}; allowed "$rel" || fail "staged path outside allowed destinations: $rel"
        dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "destination escapes prefix: $dest"
        safe_parent "$(dirname -- "$dest")"
        o=$(owner "$dest"); [[ -z "$o" ]] || fail "installer package owns $dest ($o)"
        if [[ -e "$dest" || -L "$dest" ]]; then
            index=$(old_index "$rel") || fail "unmanaged file exists: $dest"
            hash_ok "$dest" "${OLD_HASHES[$index]}" || fail "changed file preserved: $dest"
        fi
        h=$(sha256 "$path"); printf 'file\t%s\t%s\n' "$h" "$rel" >> "$STAGE_DIR/manifest-entries"; files+=("$path"); rels+=("$rel")
    done < <(find "$STAGE_DIR/bin" "$STAGE_DIR/share/baradwatchu-client" -type f -print0)
    for i in "${!OLD_RELS[@]}"; do
        rel=${OLD_RELS[$i]} present=0
        for path in "${rels[@]}"; do [[ "$path" == "$rel" ]] && present=1; done
        ((present)) && continue
        dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "old manifest path escapes prefix: $dest"
        o=$(owner "$dest"); [[ -z "$o" ]] || fail "installer package owns $dest"
        if [[ -e "$dest" || -L "$dest" ]]; then hash_ok "$dest" "${OLD_HASHES[$i]}" || fail "changed old file preserved: $dest"; fi
    done
    manifest_parent=$(canonical "$(dirname -- "$manifest")"); [[ "$manifest_parent" == "$PREFIX"/* ]] || fail 'manifest destination escapes prefix'
    safe_parent "$(dirname -- "$manifest")"
    manifest_owner=$(owner "$manifest"); [[ -z "$manifest_owner" ]] || fail "installer package owns source manifest path ($manifest_owner)"
    app_root=$(app_location)
    check_app "$app_root"
    old_root=$(old_app_root)
    echo "Staged ${#files[@]} files and $APP_NAME before modifying $PREFIX and $app_root."
    # Last steps before any file changes: stop this installation's system service, then close
    # its running agent, tray and remote links.
    service_before_files
    stop_running_instances
    for i in "${!files[@]}"; do
        rel=${rels[$i]}; dest="$PREFIX/$rel"; mkdir -p -- "$(dirname -- "$dest")"
        tmp=$(mktemp "${dest}.baradwatchu.XXXXXX")
        if ! install -m 0644 "${files[$i]}" "$tmp"; then unlink -- "$tmp"; fail "could not stage destination file: $dest"; fi
        if [[ "$rel" == "bin/$BIN" || "$rel" == "bin/$TRAY_BIN" || "$rel" == share/baradwatchu-client/catalog/checks-macos/*.sh ]]; then chmod 0755 "$tmp"; fi
        if ! mv -f -- "$tmp" "$dest"; then unlink -- "$tmp"; fail "could not replace destination file: $dest"; fi
        if index=$(old_index "$rel"); then OLD_DONE[$index]=1; fi
    done
    for i in "${!OLD_RELS[@]}"; do
        ((OLD_DONE[$i])) && continue
        [[ ! -e "$PREFIX/${OLD_RELS[$i]}" ]] || unlink -- "$PREFIX/${OLD_RELS[$i]}"
    done
    [[ -z $old_root || $old_root == "$app_root" ]] || remove_app "$old_root"
    install_app "$app_root"
    mkdir -p -- "$(dirname -- "$manifest")"; tmp=$(mktemp "${manifest}.baradwatchu.XXXXXX")
    { printf 'BaradWatchU source manifest v1\n%s\n%s\n%s\n' "$MANIFEST_KIND" "$PREFIX" "$VERSION"; cat "$STAGE_DIR/manifest-entries"; } > "$STAGE_DIR/final-manifest"
    if ! install -m 0644 "$STAGE_DIR/final-manifest" "$tmp"; then unlink -- "$tmp"; fail 'could not stage source manifest'; fi
    if ! mv -f -- "$tmp" "$manifest"; then unlink -- "$tmp"; fail 'could not replace source manifest'; fi
    echo "Installed BaradWatchU Client $VERSION. No package was changed; configuration, identities, trust stores and history were preserved."
    echo "Application: $app_root (open BaradWatchU from Launchpad or Spotlight)"
    service_after_files
    ((REEXEC)) || post_install_user
}

[[ $(uname -s) == Darwin ]] || { echo 'Error: install-macos.sh is the macOS installer; on Linux use install.sh, on Windows install.ps1' >&2; exit 2; }
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0;; -V|--version) echo "BaradWatchU Client $VERSION"; exit 0;;
        --without-tray) WITH_TRAY=0; TRAY_SET=1;; --tray-autostart) TRAY_AUTOSTART=1; TRAY_SET=1;; --no-tray-autostart) NO_TRAY_AUTOSTART=1; TRAY_SET=1;;
        --missing-deps) MISSING=1;; --reexec) REEXEC=1;; --dry-run) DRY=1;; --no-build) NO_BUILD=1;; --build-only) BUILD_ONLY=1;; --local) LOCAL=1;; -U|--uninstall) UNINSTALL=1;;
        --prefix=*) PREFIX=${1#*=}; PREFIX_SET=1;; --prefix) shift; (($#))||badarg '--prefix requires DIR'; PREFIX=$1; PREFIX_SET=1;;
        --build-dir=*) BUILD_DIR=${1#*=}; BUILD_SET=1;; --build-dir) shift; (($#))||badarg '--build-dir requires DIR'; BUILD_DIR=$1; BUILD_SET=1;;
        *) badarg "unknown option: $1";;
    esac
    shift
done
if ((MISSING)); then ((DRY+NO_BUILD+BUILD_ONLY+LOCAL+UNINSTALL+PREFIX_SET+BUILD_SET==0))||badarg '--missing-deps conflicts with other options'; print_options; deps audit && exit 0 || exit 1; fi
((BUILD_ONLY==0||DRY==0&&NO_BUILD==0&&LOCAL==0&&UNINSTALL==0&&PREFIX_SET==0))||badarg '--build-only conflicts with install options'
((BUILD_ONLY==0||BUILD_SET==1))||badarg '--build-only requires explicit --build-dir=DIR'
((LOCAL==0||PREFIX_SET==0))||badarg '--local conflicts with --prefix'
((WITH_TRAY==1||TRAY_AUTOSTART==0&&NO_TRAY_AUTOSTART==0))||badarg 'tray autostart options conflict with --without-tray'
((TRAY_AUTOSTART==0||NO_TRAY_AUTOSTART==0))||badarg '--tray-autostart conflicts with --no-tray-autostart'
((UNINSTALL==0||TRAY_SET==0))||badarg '--uninstall removes the tray when installed; tray options do not apply'
((UNINSTALL==0||NO_BUILD==0&&BUILD_SET==0))||badarg '--uninstall conflicts with build options'
if ((LOCAL)); then [[ "$EUID" != 0 && -n "${HOME:-}" ]]||fail '--local requires a non-root user with HOME'; PREFIX="$HOME/.local"; fi
[[ "$PREFIX" == /* && "$PREFIX" != / ]]||badarg '--prefix must be absolute and may not be /'
[[ -n "$BUILD_DIR" && "$PREFIX$BUILD_DIR" != *$'\n'* && "$PREFIX$BUILD_DIR" != *$'\r'* && "$PREFIX$BUILD_DIR" != *$'\t'* ]] || badarg 'paths must be non-empty and contain no tabs or newlines'
PREFIX=$(canonical "$PREFIX"); BUILD_DIR=$(canonical "$BUILD_DIR")
[[ "$PREFIX" != / ]] || badarg '--prefix resolves to /; choose a dedicated prefix'
case "$BUILD_DIR/" in "$ROOT/"*) badarg '--build-dir must be outside source tree';; esac
manifest="$PREFIX/share/baradwatchu-source/$BIN.manifest"
if [[ -e "$manifest" || -L "$manifest" ]]; then FRESH=0; else FRESH=1; fi
if ((LOCAL)) || { ((EUID != 0)) && prefix_writable; }; then SYSTEM_INSTALL=0; fi
APP_ROOT=$(app_location)
((BUILD_ONLY)) || plan_service
((REEXEC)) || print_options
if ((BUILD_ONLY)); then build; echo "Build-only complete; validated cache at $BUILD_DIR. No prefix files or services changed."; exit 0; fi
if ((UNINSTALL && DRY == 0)) && ! prefix_writable; then
    command -v sudo >/dev/null || fail "removing files from $PREFIX needs root privileges and sudo is unavailable; run as root or use a writable prefix"
    if ! authenticate_sudo; then fail "sudo authentication failed; no files were removed; rerun when sudo works"; fi
    echo "Root privileges are needed to remove files from $PREFIX; sudo will be used for manifest-owned files only."
    remove_user_autostart
    exec sudo /bin/bash "$SELF" --uninstall --prefix="$PREFIX" --reexec
fi
if ((UNINSTALL)); then ((DRY))&&echo 'Dry-run: no files/services change.'; ((REEXEC)) || ((EUID == 0)) || remove_user_autostart; uninstall; exit 0; fi
if ((DRY)); then
    if ((NO_BUILD)); then dep_mode=runtime; else dep_mode=build; fi
    deps "$dep_mode" || echo 'A real run would stop here: required dependencies are missing. No changes made.'
    if ((NO_BUILD)); then validate_build; else echo 'Plan: build unprivileged, stage artifacts, install manifest-owned files.'; fi
    echo 'Dry-run complete; no files or services changed.'; exit 0
fi
install_source
