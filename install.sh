#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
PRODUCT=Client BIN=baradwatchu-agent
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
VERSION=$(awk '/^[[:space:]]*\[workspace[.]package\]/{f=1;next} /^[[:space:]]*\[/{f=0} f&&/^[[:space:]]*version[[:space:]]*=/{split($0,a,"\"");print a[2];exit}' "$ROOT/Cargo.toml")
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo 'Invalid SemVer in Cargo.toml' >&2; exit 1; }
PREFIX=/usr/local BUILD_DIR=${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/baradwatchu/$BIN-$VERSION
LOCAL=0 UNINSTALL=0 DRY=0 NO_BUILD=0 BUILD_ONLY=0 MISSING=0 PREFIX_SET=0 BUILD_SET=0 REEXEC=0
STAGE_DIR='' WEB_BUILD_DIR=''
cleanup() {
    local path
    for path in "$STAGE_DIR" "$WEB_BUILD_DIR"; do
        if [[ -n "$path" && -d "$path" && ! -L "$path" ]]; then find "$path" -depth -delete 2>/dev/null || true; fi
    done
}
trap cleanup EXIT
# Keep execution failures distinct from invalid CLI arguments (exit 2).
trap 'exit 1' ERR
usage() { cat <<'EOF'
BaradWatchU Client source installer
Usage: ./install.sh [OPTIONS]
  -h, --help           Show help       -V, --version       Show version
      --missing-deps   Read-only dependency check: [REQUIRED] items block the
                       install, [optional] Arch audit tools only degrade checks
      --dry-run        Print plan without changing files/services
      --no-build       Reuse a validated source/platform/version build
      --build-only     Build and validate cache; do not install files
      --build-dir=DIR  Select build cache outside source tree
      --local          Limited user development copy in ~/.local
      --prefix=DIR     Install prefix (default /usr/local)
  -U, --uninstall      Remove unchanged files listed in source manifest
User-local installation is a limited development copy, not a system-wide agent.
Run as a normal user: build without root, then use sudo only to copy files into
a protected system prefix. Failed sudo authentication leaves the build cache
available for retry. No package, systemd unit, or service restart is performed.
Before files are replaced or removed, a running baradwatchu-agent of the same
installation (matched by executable path, e.g. an open dashboard) gets SIGTERM
and up to BARADWATCHU_STOP_TIMEOUT seconds (default 10); it is never killed.
EOF
}
fail() { echo "Error: $*" >&2; exit 1; }
badarg() { echo "Error: $*" >&2; usage >&2; exit 2; }
ge() { awk -v a="$1" -v b="$2" 'BEGIN{split(a,x,".");split(b,y,".");for(i=1;i<=3;i++){if(x[i]+0>y[i]+0)exit 0;if(x[i]+0<y[i]+0)exit 1}exit 0}'; }

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
    elif [[ -s /usr/share/nvm/nvm.sh ]]; then
        nvm_script=/usr/share/nvm/nvm.sh
    else
        return 1
    fi
    export NVM_DIR=$nvm_home
    # shellcheck disable=SC1090
    source "$nvm_script" >/dev/null 2>&1 || :
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
    nvm use --silent >/dev/null 2>&1 || nvm_status=$?
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
    local id='' like=''
    if [[ -r /etc/os-release ]]; then
        # Read the two keys without sourcing the host file.
        id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d "\"'")
        like=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d "\"'")
    fi
    case " ${id,,} ${like,,} " in
        *' arch '*) echo Arch ;;
        *' fedora '*|*' rhel '*) echo Fedora ;;
        *' debian '*|*' ubuntu '*) echo Debian/Ubuntu ;;
        *) echo unknown ;;
    esac
}

# deps MODE: audit (--missing-deps: report everything), build (build + runtime requirements),
# runtime (installing an existing build). Missing REQUIRED items return 1 and block the
# caller; OPTIONAL items never block. Audit-tool checks are Arch Linux only.
deps() {
    local mode=${1:-audit} family suggest_build='' suggest_runtime='' rv cv nv np libc
    local build_missing=0 runtime_missing=0 optional_missing=0 project_missing=0 node_via_nvm=0 node_missing=0
    local optional_packages='' entry binary package controls tool
    family=$(os_family)
    case $family in
        Arch) suggest_build='sudo pacman -S --needed base-devel python rust'; suggest_runtime='sudo pacman -S --needed bash python gawk sed grep coreutils' ;;
        Fedora) suggest_build='sudo dnf install gcc gcc-c++ make python3 tar rust cargo'; suggest_runtime='sudo dnf install bash python3 gawk sed grep coreutils' ;;
        Debian/Ubuntu) suggest_build='sudo apt update && sudo apt install build-essential python3 tar cargo rustc'; suggest_runtime='sudo apt install bash python3 gawk sed grep coreutils' ;;
    esac
    printf '%sDependency check: BaradWatchU Client %s (distribution family: %s)%s\n' "$C_BOLD" "$VERSION" "$family" "$C_RST"

    if [[ $mode != runtime ]]; then
        section 'Build requirements (required to compile)'
        if command -v rustc >/dev/null && rv=$(rustc --version|awk '{print $2}') && ge "$rv" 1.80.0; then dep_ok "rustc $rv"; else dep_required 'rustc >= 1.80.0'; build_missing=1; fi
        if command -v cargo >/dev/null && cv=$(cargo --version|awk '{print $2}') && ge "$cv" 1.80.0; then dep_ok "cargo $cv"; else dep_required 'cargo >= 1.80.0'; build_missing=1; fi
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
        for tool in cc c++ make tar; do
            if command -v "$tool" >/dev/null; then dep_ok "$tool"; else dep_required "build tool: $tool"; build_missing=1; fi
        done
        libc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
        if [[ "$libc" == glibc\ * ]] && ge "${libc#glibc }" 2.17.0; then dep_ok "$libc"; else dep_required 'glibc >= 2.17'; build_missing=1; fi
        if [[ -x "$ROOT/web/node_modules/.bin/ng" && -d "$ROOT/web/node_modules/@angular-devkit/build-angular" ]]; then
            dep_ok 'Angular builder packages (web/node_modules)'
        else
            project_missing=1
            dep_note 'Angular builder packages are not in web/node_modules: the build installs them in its private cache with npm ci.'
        fi
    fi

    section 'Runtime requirements (required by the agent and its checks)'
    for entry in 'bash|bash' 'python3|python' 'awk|gawk' 'sed|sed' 'grep|grep' 'od|coreutils' 'tr|coreutils' 'stat|coreutils' 'date|coreutils'; do
        IFS='|' read -r binary package <<< "$entry"
        if command -v "$binary" >/dev/null 2>&1; then dep_ok "$binary"; else dep_required "$binary (package: $package)"; runtime_missing=1; fi
    done

    if [[ $family == Arch ]]; then
        section 'Audit tools (Arch Linux only, optional: a missing tool makes its check report WARN)'
        # binary|package|purpose|alternative group (one present tool satisfies the group)
        local -a runtime_tools=(
            'checkupdates|pacman-contrib|REQ-001 updates|'
            'systemctl|systemd|REQ-002/003/004 service state|'
            'ufw|ufw|REQ-003 firewall|firewall'
            'firewall-cmd|firewalld|REQ-003 firewall|firewall'
            'nft|nftables|REQ-003 firewall|firewall'
            'dnsmasq|dnsmasq|REQ-004 DNS filter, method B (method A is a blocklist in /etc/hosts)|'
            'cato-sdp|Cato Client vendor package|REQ-005 VPN|vpn'
            'wg|wireguard-tools|REQ-005 VPN|vpn'
            'lsblk|util-linux|REQ-006 LUKS|'
            'findmnt|util-linux|REQ-006 eCryptfs/CryFS mounts|'
            'kreadconfig6|kconfig|REQ-007 KDE screen lock|'
            'pgrep|procps-ng|REQ-007 session detection|'
            'chage|shadow|REQ-008 password ageing|'
            'systemd-analyze|systemd|REQ-009 TPM2|'
            'notify-send|libnotify|audit --notify|'
            'xdg-open|xdg-utils|dashboard opens the browser|'
        )
        local group present_groups=' '
        for entry in "${runtime_tools[@]}"; do
            IFS='|' read -r binary package controls group <<< "$entry"
            [[ -n $group ]] && command -v "$binary" >/dev/null 2>&1 && present_groups+="$group "
        done
        for entry in "${runtime_tools[@]}"; do
            IFS='|' read -r binary package controls group <<< "$entry"
            if command -v "$binary" >/dev/null 2>&1; then
                dep_ok "$binary ${C_DIM}— $controls${C_RST}"
            elif [[ -n $group && $present_groups == *" $group "* ]]; then
                dep_note "  -         $binary — $controls: alternative not installed, another one is present"
            else
                [[ -z $group ]] || controls+=" (any one of the $group tools is enough)"
                dep_optional "$binary — $controls (package: $package)"
                optional_missing=$((optional_missing + 1))
                [[ $package == *' '* ]] && continue
                case " $optional_packages " in *" $package "*) ;; *) optional_packages+="$package " ;; esac
            fi
        done
    else
        section 'Audit tools'
        dep_note "Skipped: the built-in checks target Arch Linux (pacman, checkupdates, KDE Plasma)."
        dep_note "On $family the agent installs and runs, but most built-in checks report WARN or ERROR."
    fi

    section 'Summary'
    if ((build_missing || runtime_missing)); then
        printf '  %sRequired dependencies are missing: installation is blocked.%s\n' "$C_REQ" "$C_RST"
        ((build_missing == 0)) || { [[ -n $suggest_build ]] && echo "  Build tools:   $suggest_build" || echo '  Build tools:   no package command known for this distribution'; }
        ((runtime_missing == 0)) || { [[ -n $suggest_runtime ]] && echo "  Runtime tools: $suggest_runtime" || echo '  Runtime tools: no package command known for this distribution'; }
        if ((node_missing)) && ((node_via_nvm == 0)); then echo '  Node.js:       select Node.js 20 >= 20.11.1 using web/.nvmrc (with nvm: cd web && nvm install)'; fi
    else
        printf '  %sAll required dependencies are present.%s\n' "$C_OK" "$C_RST"
    fi
    if ((optional_missing)); then
        printf '  %s%s optional audit tool(s) missing%s: the related checks report WARN until installed.\n' "$C_OPT" "$optional_missing" "$C_RST"
        [[ -z $optional_packages ]] || echo "  Optional:      sudo pacman -S --needed ${optional_packages% }"
    fi
    ((node_via_nvm == 0)) || echo "  Using nvm Node.js $nv and its matching npm for this build."
    if ((project_missing)) && [[ $mode == build ]]; then echo '  Angular packages will be installed in the build cache; a --no-build install does not need them.'; fi
    if ((project_missing)) && [[ $mode == audit ]]; then echo "  Optional:      (cd '$ROOT/web' && npm ci --no-audit --no-fund) prepares a local development build"; fi
    echo
    ((build_missing == 0 && runtime_missing == 0))
}

# --- running instances (modelled on AQTRunCat's installer) ------------------
# A running agent of THIS installation (dashboard, audit) is identified by the exact
# executable path in /proc/PID/exe, never by name. This user's instances get SIGTERM and
# up to STOP_TIMEOUT seconds; nothing is SIGKILLed; other users' instances are reported.
STOP_TIMEOUT=${BARADWATCHU_STOP_TIMEOUT:-10}
[[ $STOP_TIMEOUT =~ ^[1-9][0-9]?$ ]] || { echo 'BARADWATCHU_STOP_TIMEOUT must be 1-99 seconds' >&2; exit 2; }
if [[ $EUID -eq 0 && -n ${SUDO_USER:-} && ${SUDO_USER} != root ]]; then REAL_UID=$(id -u -- "$SUDO_USER"); else REAL_UID=$EUID; fi
process_start() { # field 22 of /proc/PID/stat tells a process apart from a reused PID
    local stat; { IFS= read -r stat < "/proc/$1/stat"; } 2>/dev/null || return 1
    stat=${stat##*) }; local -a fields; read -r -a fields <<< "$stat"
    [[ ${fields[0]} != Z ]] || return 1
    printf '%s\n' "${fields[19]}"
}
process_uid() {
    local key value _
    while read -r key value _; do [[ $key == Uid: ]] && { printf '%s\n' "$value"; return 0; }; done < "/proc/$1/status" 2>/dev/null
    return 1
}
running_instances() { # "PID UID START" for each process running $PREFIX/bin/$BIN
    local dir pid comm exe installed="$PREFIX/bin/$BIN"
    for dir in /proc/[0-9]*; do
        pid=${dir#/proc/}
        { IFS= read -r comm < "$dir/comm"; } 2>/dev/null || continue
        [[ $comm == "${BIN:0:15}" ]] || continue
        exe=$(readlink -- "$dir/exe" 2>/dev/null) || continue
        exe=${exe% (deleted)}
        [[ $exe == "$installed" ]] || continue
        printf '%s %s %s\n' "$pid" "$(process_uid "$pid")" "$(process_start "$pid")"
    done
}
describe_instances() {
    local pid uid start found=0 will='will be'
    ((DRY)) && will='would be'
    while read -r pid uid start; do
        found=1
        if [[ $uid == "$REAL_UID" ]]; then option 'running' "PID $pid, $will closed (SIGTERM, up to ${STOP_TIMEOUT} s) before files change"
        else option 'running' "PID $pid of user $uid, left running (not yours)"; fi
    done < <(running_instances)
    ((found)) || option 'running' 'no instance of this installation'
}
stop_running_instances() {
    local -a pids=() starts=() others=() alive=()
    local pid uid start i waited=0
    while read -r pid uid start; do
        if [[ $uid == "$REAL_UID" ]]; then pids+=("$pid"); starts+=("$start"); else others+=("$pid"); fi
    done < <(running_instances)
    ((${#others[@]} == 0)) || echo "Warning: $BIN of this installation is also running for other users (PID ${others[*]}); it is not stopped and keeps the old files open until restarted." >&2
    ((${#pids[@]})) || return 0
    echo "Closing the running $BIN (PID ${pids[*]}) ..."
    for i in "${!pids[@]}"; do kill -TERM "${pids[$i]}" 2>/dev/null || true; done
    while :; do
        alive=()
        for i in "${!pids[@]}"; do [[ $(process_start "${pids[$i]}" 2>/dev/null) == "${starts[$i]}" ]] && alive+=("${pids[$i]}"); done
        ((${#alive[@]})) || break
        ((waited < STOP_TIMEOUT * 10)) || fail "$BIN (PID ${alive[*]}) did not exit within ${STOP_TIMEOUT} s after SIGTERM; nothing was changed. Close it (Ctrl+C in its terminal) and run the installer again."
        sleep 0.1; waited=$((waited + 1))
    done
    echo "$BIN closed. Start the dashboard again with: $BIN dashboard"
}
print_options() { # every run starts with the effective plan
    local action=install privileges=none
    ((UNINSTALL)) && action=uninstall
    ((BUILD_ONLY)) && action='build only'
    ((MISSING)) && action='dependency check'
    prefix_writable || privileges='sudo, only for copying/removing files'
    printf '%sBaradWatchU Client %s installer%s\n' "$C_BOLD" "$VERSION" "$C_RST"
    option 'action' "$action$( ((DRY)) && echo ' (dry run: nothing changes)')"
    if ((MISSING == 0)); then
        if ((LOCAL)); then option 'scope' "current user only ($PREFIX)"; else option 'scope' "system-wide ($PREFIX)"; fi
        if ((UNINSTALL == 0)); then
            if ((NO_BUILD)); then option 'build' "reuse $BUILD_DIR (--no-build)"; else option 'build' "compile in $BUILD_DIR"; fi
        fi
        option 'binary' "$PREFIX/bin/$BIN"
        option 'manifest' "$manifest"
        ((BUILD_ONLY)) || option 'privileges' "$privileges"
        option 'user data' "kept: \$XDG_CONFIG_HOME/baradwatchu (settings, custom-checks) and \$XDG_STATE_HOME/baradwatchu (audit history)"
        ((BUILD_ONLY)) || describe_instances
    fi
    option 'distribution' "$(os_family)"
    echo
}

canonical() { realpath -m -- "$1"; }
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
    (cd "$ROOT"; local paths=(Cargo.toml install.sh crates catalog web); [[ ! -f Cargo.lock ]] || paths+=(Cargo.lock); [[ ! -d .cargo ]] || paths+=(.cargo); find "${paths[@]}" -type d \( -name .git -o -name target -o -name node_modules -o -name dist -o -name .angular -o -name out-tsc \) -prune -o \( -type f -o -type l \) -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
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
    (cd "$BUILD_DIR"; { printf '%s\0' "cargo-target/release/$BIN"; find cargo-target/share/baradwatchu-client angular/browser -type f -print0; } | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
}
validate_build() {
    local m="$BUILD_DIR/.baradwatchu-build" platform libc built_libc
    platform="$(uname -s)-$(uname -m)"
    [[ -f "$m" && ! -L "$m" && $(sed -n '1p' "$m") == 'BaradWatchU build marker v2' ]] || fail "no current build cache at $BUILD_DIR; rebuild with --build-only"
    [[ $(mvget product "$m") == client && $(mvget source "$m") == "$ROOT" ]] || fail 'build cache source/product mismatch'
    [[ $(mvget state "$m") == complete ]] || fail 'build cache is incomplete'
    [[ $(mvget platform "$m") == "$platform" && $(mvget version "$m") == "$VERSION" ]] || fail 'build cache platform/version mismatch'
    libc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true); built_libc=$(mvget libc "$m")
    [[ "$libc" == glibc\ * && "$built_libc" =~ ^[0-9]+\.[0-9]+$ ]] || fail 'build cache has no supported glibc metadata; rebuild on this host'
    ge "${libc#glibc }" "$built_libc" || fail 'build cache requires a newer glibc; rebuild on this host'
    web_ok || fail 'Angular version metadata mismatch; run node web/sync-version.mjs and rebuild'
    [[ $(mvget fingerprint "$m") == "$(fingerprint)" ]] || fail 'build cache is stale for current sources'
    [[ -x "$BUILD_DIR/cargo-target/release/$BIN" && ! -L "$BUILD_DIR/cargo-target/release/$BIN" ]] || fail 'release executable missing or unsafe'
    validate_requirement_assets "$BUILD_DIR/cargo-target" || fail 'cached check folders or trusted builtin hashes are incomplete or unsafe; rebuild'
    [[ -s "$BUILD_DIR/angular/browser/index.html" ]] || fail 'Angular assets incomplete'
    [[ -n "$(find "$BUILD_DIR/angular/browser" -type f -name '*.js' -print -quit)" ]] || fail 'Angular JavaScript bundle missing'
    [[ ! -L "$BUILD_DIR/angular" && ! -L "$BUILD_DIR/angular/browser" && -z "$(find "$BUILD_DIR/angular/browser" -type l -print -quit)" ]] || fail 'symlinks are not allowed in built web assets'
    [[ $(mvget artifacts "$m") == "$(artifact_fingerprint)" ]] || fail 'cached artifacts changed; rebuild with --build-only'
    echo "Validated build $BUILD_DIR ($platform, $VERSION)"
}
validate_requirement_assets() {
    python3 -c '
import hashlib, json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
base = "share/baradwatchu-client/"
checks_relative = base + "catalog/checks"
required_helpers = [
    "catalog/checks/REQ-003/ufw.sh", "catalog/checks/REQ-003/firewalld.sh",
    "catalog/checks/REQ-003/nftables.sh",
    "catalog/checks/REQ-004/dnsmasq.sh", "catalog/checks/REQ-004/hosts.sh",
    "catalog/checks/REQ-005/cato.sh", "catalog/checks/REQ-005/wireguard.sh",
    "catalog/checks/REQ-006/luks.sh", "catalog/checks/REQ-006/ecryptfs.sh",
    "catalog/checks/REQ-006/cryfs.sh",
]
try:
    def safe_file(relative, executable=False):
        parts = pathlib.Path(relative).parts
        if any((root / pathlib.Path(*parts[:index])).is_symlink() for index in range(1, len(parts) + 1)):
            return False
        path = root / relative
        return path.is_file() and (not executable or os.access(path, os.X_OK))
    checks_dir = root / checks_relative
    if checks_dir.is_symlink() or not checks_dir.is_dir():
        raise ValueError("check folders missing or symlink")
    if (root / "share/baradwatchu-client/tools").exists() or (root / "share/baradwatchu-client/tools").is_symlink():
        raise ValueError("obsolete duplicated tools tree remains in staged runtime")
    digest_path = root / "share/baradwatchu-client/catalog/builtin-tools.sha256"
    if not safe_file("share/baradwatchu-client/catalog/builtin-tools.sha256"):
        raise ValueError("builtin hash manifest missing or symlink")
    hashes = {}
    for line in digest_path.read_text(encoding="ascii").splitlines():
        ident, platform, tool, digest = line.split()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid builtin hash entry")
        hashes[(ident, platform)] = (tool, digest)
    discovered = set()
    for folder in checks_dir.iterdir():
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError("unsafe check folder")
        ident = folder.name
        config_relative = f"{checks_relative}/{ident}/configuration.json"
        if not safe_file(config_relative):
            raise ValueError("check configuration missing or symlink")
        config = json.loads((root / config_relative).read_text(encoding="utf-8"))
        if config.get("id") != ident or config.get("schemaVersion") != "baradwatchu.custom-checks.v1":
            raise ValueError("invalid check configuration identity")
        tool_path = pathlib.Path(config.get("toolPath", ""))
        if tool_path.is_absolute() or any(part in ("..", "") for part in tool_path.parts):
            raise ValueError("unsafe relative tool path")
        relative = f"{checks_relative}/{ident}/{tool_path}"
        if not safe_file(relative, executable=True):
            raise ValueError("tool missing, non-executable, or symlink")
        digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        entry = hashes.get((ident, "linux"))
        asset_relative = relative.removeprefix(base)
        if entry != (asset_relative, digest) or config.get("expectedSha256") != digest:
            raise ValueError("builtin tool hash manifest mismatch")
        if ident in discovered:
            raise ValueError("duplicate check ID")
        discovered.add(ident)
    if not discovered or {ident for ident, platform in hashes if platform == "linux"} != discovered:
        raise ValueError("builtin hash manifest does not match discovered folders")
    for relative in required_helpers:
        if not safe_file("share/baradwatchu-client/" + relative, executable=True):
            raise ValueError("method tool missing, non-executable, or symlink")
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
build() {
    local source_before libc
    (( EUID != 0 )) || fail 'refusing to build as root; build as user, then install with --no-build'
    deps build || fail 'required dependencies are missing (see the [REQUIRED] items above); nothing was built or installed'
    [[ -f "$ROOT/Cargo.lock" && -f "$ROOT/web/package-lock.json" ]] || fail 'Cargo.lock and web/package-lock.json are required; resolve dependencies before building'
    web_ok || node "$ROOT/web/sync-version.mjs"
    source_before=$(fingerprint)
    libc=$(getconf GNU_LIBC_VERSION); libc=${libc#glibc }
    prepare_cache
    (cd "$ROOT" && CARGO_TARGET_DIR="$BUILD_DIR/cargo-target" cargo build --release --workspace --locked)
    # npm ci removes node_modules: use a private workspace, never the checkout.
    WEB_BUILD_DIR=$(mktemp -d "$BUILD_DIR/web-source.XXXXXX")
    cp -- "$ROOT/Cargo.toml" "$WEB_BUILD_DIR/Cargo.toml"
    (cd "$ROOT" && tar --exclude=web/node_modules --exclude=web/dist --exclude=web/.angular --exclude=web/out-tsc -cf - web) | tar -C "$WEB_BUILD_DIR" -xf -
    (cd "$WEB_BUILD_DIR/web"; export npm_config_cache="${npm_config_cache:-$BUILD_DIR/npm-cache}" npm_config_devdir="$BUILD_DIR/node-gyp"; npm ci --no-audit --no-fund && npm run build -- --output-path="$BUILD_DIR/angular")
    [[ "$source_before" == "$(fingerprint)" ]] || fail 'sources changed during build; retry with a stable checkout'
    [[ -x "$BUILD_DIR/cargo-target/release/$BIN" && -s "$BUILD_DIR/angular/browser/index.html" && -n "$(find "$BUILD_DIR/angular/browser" -type f -name '*.js' -print -quit)" ]] || fail 'native build is incomplete; check Cargo target configuration'
    [[ $("$BUILD_DIR/cargo-target/release/$BIN" --version) == "BaradWatchU $PRODUCT $VERSION" ]] || fail 'built version mismatch'
    printf 'BaradWatchU build marker v2\nproduct=client\nsource=%s\nstate=complete\nplatform=%s\nversion=%s\nlibc=%s\nfingerprint=%s\nartifacts=%s\n' "$ROOT" "$(uname -s)-$(uname -m)" "$VERSION" "$libc" "$source_before" "$(artifact_fingerprint)" > "$BUILD_DIR/.baradwatchu-build"
    validate_build
}
owner() {
    local p=$1 o
    if command -v pacman >/dev/null && o=$(pacman -Qo -- "$p" 2>/dev/null); then printf '%s\n' "$o"; return; fi
    if command -v dpkg-query >/dev/null && o=$(dpkg-query -S "$p" 2>/dev/null); then printf '%s\n' "$o"; return; fi
    # rpm reports "not owned" on stdout with exit 1; output alone is not ownership.
    if command -v rpm >/dev/null && o=$(rpm -qf "$p" 2>/dev/null); then printf '%s\n' "$o"; fi
    return 0
}
allowed() { [[ "$1" != /* && "$1" != *'..'* && ( "$1" == "bin/$BIN" || "$1" == share/baradwatchu-client/* ) ]]; }
manifest="$PREFIX/share/baradwatchu-source/$BIN.manifest"
load_manifest() {
    local line k h p
    [[ -f "$manifest" && ! -L "$manifest" && $(sed -n '1p' "$manifest") == 'BaradWatchU source manifest v1' && $(sed -n '2p' "$manifest") == client && $(sed -n '3p' "$manifest") == "$PREFIX" ]] || fail 'source manifest missing, unsafe or mismatched'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS=$'\t' read -r k h p <<< "$line"
        if [[ "$k" != file || ! "$h" =~ ^[a-f0-9]{64}$ ]] || ! allowed "$p"; then fail 'invalid manifest ownership entry'; fi
    done < <(tail -n +5 "$manifest")
}
hash_ok() { [[ -f "$1" && ! -L "$1" && $(sha256sum -- "$1"|awk '{print $1}') == "$2" ]]; }
# Same deployment boundary as runtime: root or installing user, no writable
# group/other ancestors except trusted sticky directories such as /tmp.
safe_parent() {
    local path=$1 uid mode root_uid
    root_uid=$(stat -c %u /)
    while [[ "$path" != / ]]; do
        [[ ! -L "$path" ]] || fail "symlink in installation path: $path"
        if [[ -e "$path" ]]; then
            [[ -d "$path" ]] || fail "non-directory installation parent: $path"
            uid=$(stat -c %u -- "$path"); mode=$(stat -c %a -- "$path")
            [[ "$uid" == "$EUID" || "$uid" == "$root_uid" ]] || fail "untrusted installation directory owner: $path"
            (( (8#$mode & 0022) == 0 || (8#$mode & 01000) != 0 )) || fail "writable group/other installation directory: $path"
        fi
        path=$(dirname -- "$path")
    done
}
uninstall() {
    local line k h p path o parent manifest_parent count=0
    manifest_parent=$(canonical "$(dirname -- "$manifest")"); [[ "$manifest_parent" == "$PREFIX"/* ]] || fail 'manifest path escapes prefix'
    o=$(owner "$manifest"); [[ -z "$o" ]] || fail "package manager owns source manifest ($o)"
    load_manifest
    # Preflight every owned path before removing any of them, so a modified
    # later entry cannot cause a partially completed uninstall.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue; IFS=$'\t' read -r k h p <<< "$line"; path="$PREFIX/$p"
        parent=$(canonical "$(dirname -- "$path")"); [[ "$parent" == "$PREFIX"/* ]] || fail "manifest path escapes prefix: $path"
        o=$(owner "$path"); [[ -z "$o" ]] || fail "package manager owns $path ($o)"
        if [[ -e "$path" || -L "$path" ]]; then hash_ok "$path" "$h" || fail "changed file preserved: $path"; fi
    done < <(tail -n +5 "$manifest")
    ((DRY)) || stop_running_instances
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue; IFS=$'\t' read -r k h p <<< "$line"; path="$PREFIX/$p"
        parent=$(canonical "$(dirname -- "$path")"); [[ "$parent" == "$PREFIX"/* ]] || fail "manifest path escapes prefix: $path"
        o=$(owner "$path"); [[ -z "$o" ]] || fail "package manager owns $path ($o)"
        if [[ -e "$path" || -L "$path" ]]; then hash_ok "$path" "$h" || fail "changed file preserved: $path"; if ((DRY)); then echo "Would remove $path"; else unlink -- "$path"; fi; ((count+=1)); fi
    done < <(tail -n +5 "$manifest")
    if ((DRY)); then echo "Would remove $manifest"; else unlink -- "$manifest"; echo 'Manifest removed; configuration and user data preserved.'; fi
    echo "Uninstall complete; $count files processed. Empty directories remain."
}
install_source() {
    local app=share/baradwatchu-client/web path rel dest parent o h line tmp i manifest_parent manifest_owner
    local -A old=(); local -a files=() rels=()
    [[ ! -e "$PREFIX" || -d "$PREFIX" ]] || fail 'prefix exists and is not a directory'
    if ((NO_BUILD)); then
        ((REEXEC)) || deps runtime || fail 'required runtime dependencies are missing (see the [REQUIRED] items above); nothing was installed'
        validate_build
    else build; fi
    if ! prefix_writable; then
        command -v sudo >/dev/null || fail "writing to $PREFIX needs root privileges and sudo is unavailable; run as root with --no-build --build-dir='$BUILD_DIR' or use --local"
        if ! authenticate_sudo; then fail "sudo authentication failed; the validated build is kept at $BUILD_DIR; rerun with --no-build --build-dir='$BUILD_DIR' after sudo works"; fi
        echo "Root privileges are needed to write to $PREFIX; sudo will be used for file installation only."
        exec sudo "$ROOT/install.sh" --no-build --build-dir="$BUILD_DIR" --prefix="$PREFIX" --reexec
    fi
    safe_parent "$PREFIX"
    STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/baradwatchu-client-stage.XXXXXX")
    install -D -m 0755 "$BUILD_DIR/cargo-target/release/$BIN" "$STAGE_DIR/bin/$BIN"
    mkdir -p "$STAGE_DIR/share/baradwatchu-client"
    cp -a "$BUILD_DIR/cargo-target/share/baradwatchu-client/." "$STAGE_DIR/share/baradwatchu-client/"
    mkdir -p "$STAGE_DIR/$app"; cp -a "$BUILD_DIR/angular/browser/." "$STAGE_DIR/$app/"
    : > "$STAGE_DIR/manifest-entries"
    if [[ -e "$manifest" || -L "$manifest" ]]; then
        load_manifest
        while IFS= read -r line; do [[ -z "$line" ]] && continue; IFS=$'\t' read -r _ h rel <<< "$line"; old["$rel"]=$h; done < <(tail -n +5 "$manifest")
    fi
    while IFS= read -r -d '' path; do
        rel=${path#"$STAGE_DIR"/}; allowed "$rel" || fail "staged path outside allowed destinations: $rel"
        dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "destination escapes prefix: $dest"
        safe_parent "$(dirname -- "$dest")"
        o=$(owner "$dest"); [[ -z "$o" ]] || fail "package manager owns $dest ($o)"
        if [[ -e "$dest" || -L "$dest" ]]; then [[ -n "${old[$rel]:-}" ]] || fail "unmanaged file exists: $dest"; hash_ok "$dest" "${old[$rel]}" || fail "changed file preserved: $dest"; fi
        h=$(sha256sum -- "$path"|awk '{print $1}'); printf 'file\t%s\t%s\n' "$h" "$rel" >> "$STAGE_DIR/manifest-entries"; files+=("$path"); rels+=("$rel")
    done < <(find "$STAGE_DIR/bin" "$STAGE_DIR/share/baradwatchu-client" -type f -print0)
    for rel in "${!old[@]}"; do
        local present=0; for path in "${rels[@]}"; do [[ "$path" == "$rel" ]] && present=1; done
        ((present)) && continue; dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "old manifest path escapes prefix: $dest"; o=$(owner "$dest"); [[ -z "$o" ]] || fail "package manager owns $dest"; if [[ -e "$dest" || -L "$dest" ]]; then hash_ok "$dest" "${old[$rel]}" || fail "changed old file preserved: $dest"; fi
    done
    manifest_parent=$(canonical "$(dirname -- "$manifest")"); [[ "$manifest_parent" == "$PREFIX"/* ]] || fail 'manifest destination escapes prefix'
    safe_parent "$(dirname -- "$manifest")"
    manifest_owner=$(owner "$manifest"); [[ -z "$manifest_owner" ]] || fail "package manager owns source manifest path ($manifest_owner)"
    echo "Staged ${#files[@]} files before modifying $PREFIX."
    # Last step before any file changes: close this installation's running agent.
    stop_running_instances
    for i in "${!files[@]}"; do
        rel=${rels[$i]}; dest="$PREFIX/$rel"; mkdir -p -- "$(dirname -- "$dest")"
        tmp=$(mktemp "${dest}.baradwatchu.XXXXXX")
        if ! install -m 0644 "${files[$i]}" "$tmp"; then unlink -- "$tmp"; fail "could not stage destination file: $dest"; fi
        if [[ "$rel" == "bin/$BIN" || "$rel" == share/baradwatchu-client/catalog/checks/*/*.sh ]]; then chmod 0755 "$tmp"; fi
        if ! mv -f -- "$tmp" "$dest"; then unlink -- "$tmp"; fail "could not replace destination file: $dest"; fi
        unset 'old[$rel]'
    done
    for rel in "${!old[@]}"; do [[ ! -e "$PREFIX/$rel" ]] || unlink -- "$PREFIX/$rel"; done
    mkdir -p -- "$(dirname -- "$manifest")"; tmp=$(mktemp "${manifest}.baradwatchu.XXXXXX")
    { printf 'BaradWatchU source manifest v1\nclient\n%s\n%s\n' "$PREFIX" "$VERSION"; cat "$STAGE_DIR/manifest-entries"; } > "$STAGE_DIR/final-manifest"
    if ! install -m 0644 "$STAGE_DIR/final-manifest" "$tmp"; then unlink -- "$tmp"; fail 'could not stage source manifest'; fi
    if ! mv -f -- "$tmp" "$manifest"; then unlink -- "$tmp"; fail 'could not replace source manifest'; fi
    echo "Installed BaradWatchU Client $VERSION. No packages/services were changed; configuration and user data were preserved."
}

while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0;; -V|--version) echo "BaradWatchU Client $VERSION"; exit 0;;
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
((UNINSTALL==0||NO_BUILD==0&&BUILD_SET==0))||badarg '--uninstall conflicts with build options'
if ((LOCAL)); then [[ "$EUID" != 0 && -n "${HOME:-}" ]]||fail '--local requires a non-root user with HOME'; PREFIX="$HOME/.local"; fi
[[ "$PREFIX" == /* && "$PREFIX" != / ]]||badarg '--prefix must be absolute and may not be /'
[[ -n "$BUILD_DIR" && "$PREFIX$BUILD_DIR" != *$'\n'* && "$PREFIX$BUILD_DIR" != *$'\r'* && "$PREFIX$BUILD_DIR" != *$'\t'* ]] || badarg 'paths must be non-empty and contain no tabs or newlines'
PREFIX=$(canonical "$PREFIX"); BUILD_DIR=$(canonical "$BUILD_DIR")
[[ "$PREFIX" != / ]] || badarg '--prefix resolves to /; choose a dedicated prefix'
case "$BUILD_DIR/" in "$ROOT/"*) badarg '--build-dir must be outside source tree';; esac
manifest="$PREFIX/share/baradwatchu-source/$BIN.manifest"
((REEXEC)) || print_options
if ((BUILD_ONLY)); then build; echo "Build-only complete; validated cache at $BUILD_DIR. No prefix files or services changed."; exit 0; fi
if ((UNINSTALL && DRY == 0)) && ! prefix_writable; then
    command -v sudo >/dev/null || fail "removing files from $PREFIX needs root privileges and sudo is unavailable; run as root or use a writable prefix"
    if ! authenticate_sudo; then fail "sudo authentication failed; no files were removed; rerun when sudo works"; fi
    echo "Root privileges are needed to remove files from $PREFIX; sudo will be used for manifest-owned files only."
    exec sudo "$ROOT/install.sh" --uninstall --prefix="$PREFIX" --reexec
fi
if ((UNINSTALL)); then ((DRY))&&echo 'Dry-run: no files/services change.'; uninstall; exit 0; fi
if ((DRY)); then
    if ((NO_BUILD)); then dep_mode=runtime; else dep_mode=build; fi
    deps "$dep_mode" || echo 'A real run would stop here: required dependencies are missing. No changes made.'
    if ((NO_BUILD)); then validate_build; else echo 'Plan: build unprivileged, stage artifacts, install manifest-owned files.'; fi
    echo 'Dry-run complete; no files or services changed.'; exit 0
fi
install_source
