#!/usr/bin/env bash
set -Eeuo pipefail
PRODUCT=Client BIN=baradwatchu-agent
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
VERSION=$(awk '/^\[workspace.package\]/{f=1;next} /^\[/{f=0} f&&$1=="version"{gsub(/"/,"",$3);print $3;exit}' "$ROOT/Cargo.toml")
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo 'Invalid SemVer in Cargo.toml' >&2; exit 1; }
PREFIX=/usr/local BUILD_DIR=${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/baradwatchu/$BIN-$VERSION
LOCAL=0 UNINSTALL=0 DRY=0 NO_BUILD=0 BUILD_ONLY=0 MISSING=0 PREFIX_SET=0 BUILD_SET=0
usage() { cat <<'EOF'
BaradWatchU Client source installer
Usage: ./install.sh [OPTIONS]
  -h, --help           Show help       -V, --version       Show version
      --missing-deps   Read-only dependency audit
      --dry-run        Print plan without changing files/services
      --no-build       Reuse a validated source/platform/version build
      --build-only     Build and validate cache; do not install files
      --build-dir=DIR  Select build cache outside source tree
      --local          Limited user development copy in ~/.local
      --prefix=DIR     Install prefix (default /usr/local)
  -U, --uninstall      Remove unchanged files listed in source manifest
User-local installation is a limited development copy, not a system-wide agent.
No package install, systemd unit creation, or service restart is performed.
EOF
}
fail() { echo "Error: $*" >&2; exit 1; }
badarg() { echo "Error: $*" >&2; usage >&2; exit 2; }
ge() { awk -v a="$1" -v b="$2" 'BEGIN{split(a,x,".");split(b,y,".");for(i=1;i<=3;i++){if(x[i]+0>y[i]+0)exit 0;if(x[i]+0<y[i]+0)exit 1}exit 0}'; }

deps() {
    local mode=${1:-audit} id='' like='' family=unknown suggest='' rv cv nv np libc missing=0 project_missing=0
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release; id=${ID:-}; like=${ID_LIKE:-}; id=${id,,}; like=${like,,}
    fi
    case " $id $like " in
        *' arch '*) family=Arch; suggest='sudo pacman -S --needed rust nodejs npm' ;;
        *' fedora '*|*' rhel '*) family=Fedora; suggest='sudo dnf install rust cargo nodejs npm' ;;
        *' debian '*|*' ubuntu '*) family=Debian/Ubuntu; suggest='sudo apt update && sudo apt install cargo rustc nodejs npm' ;;
    esac
    echo "Dependency audit: Client $VERSION ($family)"
    if command -v rustc >/dev/null && rv=$(rustc --version|awk '{print $2}') && ge "$rv" 1.80.0; then echo "[ok] rustc $rv"; else echo '[missing] rustc >=1.80.0'; missing=1; fi
    if command -v cargo >/dev/null && cv=$(cargo --version|awk '{print $2}') && ge "$cv" 1.80.0; then echo "[ok] Cargo $cv"; else echo '[missing] Cargo >=1.80.0'; missing=1; fi
    if command -v node >/dev/null && nv=$(node -p 'process.versions.node') && ge "$nv" 20.11.0; then echo "[ok] Node.js $nv"; else echo '[missing] Node.js >=20.11.0 (Angular 18)'; missing=1; fi
    if command -v npm >/dev/null && np=$(npm --version) && ge "$np" 8.0.0; then echo "[ok] npm $np"; else echo '[missing] npm >=8.0.0'; missing=1; fi
    libc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
    if [[ "$libc" == glibc\ * ]] && ge "${libc#glibc }" 2.17.0; then echo "[ok] $libc runtime"; else echo '[missing] glibc >=2.17 runtime'; missing=1; fi
    if [[ -x "$ROOT/web/node_modules/.bin/ng" && -d "$ROOT/web/node_modules/@angular-devkit/build-angular" ]]; then
        echo '[ok] local Angular builder dependencies'
    else
        echo '[missing project dependencies] Angular builder packages (source build can fetch these with npm install)'
        project_missing=1
    fi
    echo 'Optional dependencies:'
    for tool in systemctl xdg-open shellcheck; do if command -v "$tool" >/dev/null; then echo "  [optional present] $tool"; else echo "  [optional absent] $tool"; fi; done
    echo '  systemctl service integration and xdg-open viewer launch are deferred.'
    if (( missing )); then
        [[ -z "$suggest" ]] || echo "Suggested package command: $suggest"
        (( project_missing == 0 )) || echo "Suggested project command: (cd '$ROOT/web' && npm install --no-audit --no-fund)"
        [[ "$family" != Debian/Ubuntu ]] || echo 'Ensure configured repositories provide Node.js >=20.11.0 and npm >=8.0.0.'
        [[ -n "$suggest" ]] || echo 'No package command suggested for this distribution family.'
        return 1
    fi
    if (( project_missing )) && [[ "$mode" == audit ]]; then
        echo "Suggested project command: (cd '$ROOT/web' && npm install --no-audit --no-fund)"
        return 1
    fi
    (( project_missing == 0 )) || echo 'Angular packages will be installed locally by the source build; a --no-build install does not need them.'
    return 0
}

canonical() { realpath -m -- "$1"; }
prefix_writable() { local p="$PREFIX"; (( EUID == 0 )) && return 0; while [[ ! -e "$p" ]]; do p=$(dirname -- "$p"); done; [[ -d "$p" && -w "$p" && -x "$p" ]]; }
fingerprint() { (cd "$ROOT"; find Cargo.toml crates web -type d \( -name .git -o -name target -o -name node_modules -o -name dist -o -name .angular \) -prune -o -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'); }
web_ok() {
    local pv av
    pv=$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([0-9.]*\)".*/\1/p' "$ROOT/web/package.json"|head -1)
    av=$(sed -n "s/^export const APP_VERSION = '\([^']*\)';$/\1/p" "$ROOT/web/src/app-version.ts")
    [[ "$pv" == "$VERSION" && "$av" == "$VERSION" ]]
}
mvget() { sed -n "s/^$1=//p" "$2"|head -1; }
validate_build() {
    local m="$BUILD_DIR/.baradwatchu-build" platform
    platform="$(uname -s)-$(uname -m)"
    [[ -f "$m" && ! -L "$m" && $(sed -n '1p' "$m") == 'BaradWatchU build marker v1' ]] || fail "no recognized build cache at $BUILD_DIR"
    [[ $(mvget product "$m") == client && $(mvget source "$m") == "$ROOT" ]] || fail 'build cache source/product mismatch'
    [[ $(mvget platform "$m") == "$platform" && $(mvget version "$m") == "$VERSION" ]] || fail 'build cache platform/version mismatch'
    web_ok || fail 'Angular version metadata mismatch; run node web/sync-version.mjs and rebuild'
    [[ $(mvget fingerprint "$m") == "$(fingerprint)" ]] || fail 'build cache is stale for current sources'
    [[ -x "$BUILD_DIR/cargo-target/release/$BIN" ]] || fail 'release executable missing'
    [[ $("$BUILD_DIR/cargo-target/release/$BIN" --version 2>/dev/null) == "BaradWatchU $PRODUCT $VERSION" ]] || fail 'release binary version mismatch'
    [[ -s "$BUILD_DIR/angular/browser/index.html" ]] || fail 'Angular assets incomplete'
    [[ -n "$(find "$BUILD_DIR/angular/browser" -type f -name '*.js' -print -quit)" ]] || fail 'Angular JavaScript bundle missing'
    echo "Validated build $BUILD_DIR ($platform, $VERSION)"
}
prepare_cache() {
    local m="$BUILD_DIR/.baradwatchu-build" found
    if [[ -e "$BUILD_DIR" ]]; then
        [[ -d "$BUILD_DIR" && ! -L "$BUILD_DIR" ]] || fail 'build dir must be a real directory'
        if [[ -e "$m" ]]; then
            [[ -f "$m" && ! -L "$m" && $(sed -n '1p' "$m") == 'BaradWatchU build marker v1' ]] || fail 'unrecognized build marker'
            [[ $(mvget product "$m") == client && $(mvget source "$m") == "$ROOT" ]] || fail 'build dir is marked for another source/product'
        else
            found=$(find "$BUILD_DIR" -mindepth 1 -print -quit); [[ -z "$found" ]] || fail 'refusing non-empty, unmarked build directory'
        fi
    else mkdir -p -- "$BUILD_DIR"; fi
    printf 'BaradWatchU build marker v1\nproduct=client\nsource=%s\nstate=incomplete\n' "$ROOT" > "$m"
}
build() {
    (( EUID != 0 )) || fail 'refusing to build as root; build as user, then install with --no-build'
    deps build || fail 'required system build dependencies are missing'
    web_ok || node "$ROOT/web/sync-version.mjs"
    prepare_cache
    CARGO_TARGET_DIR="$BUILD_DIR/cargo-target" cargo build --manifest-path "$ROOT/Cargo.toml" --release --workspace
    if [[ -f "$ROOT/web/package-lock.json" ]]; then (cd "$ROOT/web" && npm ci --no-audit --no-fund); else (cd "$ROOT/web" && npm install --no-audit --no-fund); fi
    (cd "$ROOT/web" && npm run build -- --output-path="$BUILD_DIR/angular")
    [[ -x "$BUILD_DIR/cargo-target/release/$BIN" && -s "$BUILD_DIR/angular/browser/index.html" && -n "$(find "$BUILD_DIR/angular/browser" -type f -name '*.js' -print -quit)" ]] || fail 'build is incomplete'
    [[ $("$BUILD_DIR/cargo-target/release/$BIN" --version) == "BaradWatchU $PRODUCT $VERSION" ]] || fail 'built version mismatch'
    printf 'BaradWatchU build marker v1\nproduct=client\nsource=%s\nplatform=%s\nversion=%s\nfingerprint=%s\n' "$ROOT" "$(uname -s)-$(uname -m)" "$VERSION" "$(fingerprint)" > "$BUILD_DIR/.baradwatchu-build"
    validate_build
}
owner() { local p=$1 o=''; command -v pacman >/dev/null && o=$(pacman -Qo -- "$p" 2>/dev/null||true); [[ -n "$o" ]] || { command -v dpkg-query >/dev/null && o=$(dpkg-query -S "$p" 2>/dev/null||true); }; [[ -n "$o" ]] || { command -v rpm >/dev/null && o=$(rpm -qf "$p" 2>/dev/null||true); }; [[ -z "$o" ]] || echo "$o"; }
allowed() { [[ "$1" != /* && "$1" != *'..'* && ( "$1" == "bin/$BIN" || "$1" == share/baradwatchu-client/web/* ) ]]; }
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
uninstall() {
    local line k h p path o parent manifest_parent count=0
    manifest_parent=$(canonical "$(dirname -- "$manifest")"); [[ "$manifest_parent" == "$PREFIX"/* ]] || fail 'manifest path escapes prefix'
    o=$(owner "$manifest"); [[ -z "$o" ]] || fail "package manager owns source manifest ($o)"
    load_manifest
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
    local app=share/baradwatchu-client/web stage path rel dest parent o h line tmp i manifest_parent manifest_owner
    local -A old=(); local -a files=() rels=()
    [[ ! -e "$PREFIX" || -d "$PREFIX" ]] || fail 'prefix exists and is not a directory'
    prefix_writable || fail "prefix is not writable; run --build-only as user, then sudo ./install.sh --no-build --build-dir='$BUILD_DIR' --prefix='$PREFIX'"
    if ((NO_BUILD)); then validate_build; else build; fi
    stage=$(mktemp -d "${TMPDIR:-/tmp}/baradwatchu-client-stage.XXXXXX")
    trap 'find "$stage" -depth -type f -delete 2>/dev/null || true; find "$stage" -depth -type d -empty -delete 2>/dev/null || true' EXIT
    install -D -m 0755 "$BUILD_DIR/cargo-target/release/$BIN" "$stage/bin/$BIN"
    mkdir -p "$stage/$app"; cp -a "$BUILD_DIR/angular/browser/." "$stage/$app/"
    : > "$stage/manifest-entries"
    if [[ -e "$manifest" || -L "$manifest" ]]; then
        load_manifest
        while IFS= read -r line; do [[ -z "$line" ]] && continue; IFS=$'\t' read -r _ h rel <<< "$line"; old["$rel"]=$h; done < <(tail -n +5 "$manifest")
    fi
    while IFS= read -r -d '' path; do
        rel=${path#"$stage"/}; allowed "$rel" || fail "staged path outside allowed destinations: $rel"
        dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "destination escapes prefix: $dest"
        o=$(owner "$dest"); [[ -z "$o" ]] || fail "package manager owns $dest ($o)"
        if [[ -e "$dest" || -L "$dest" ]]; then [[ -n "${old[$rel]:-}" ]] || fail "unmanaged file exists: $dest"; hash_ok "$dest" "${old[$rel]}" || fail "changed file preserved: $dest"; fi
        h=$(sha256sum -- "$path"|awk '{print $1}'); printf 'file\t%s\t%s\n' "$h" "$rel" >> "$stage/manifest-entries"; files+=("$path"); rels+=("$rel")
    done < <(find "$stage/bin" "$stage/$app" -type f -print0)
    for rel in "${!old[@]}"; do
        local present=0; for path in "${rels[@]}"; do [[ "$path" == "$rel" ]] && present=1; done
        ((present)) && continue; dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "old manifest path escapes prefix: $dest"; o=$(owner "$dest"); [[ -z "$o" ]] || fail "package manager owns $dest"; [[ ! -e "$dest" ]] || hash_ok "$dest" "${old[$rel]}" || fail "changed old file preserved: $dest"
    done
    manifest_parent=$(canonical "$(dirname -- "$manifest")"); [[ "$manifest_parent" == "$PREFIX"/* ]] || fail 'manifest destination escapes prefix'
    manifest_owner=$(owner "$manifest"); [[ -z "$manifest_owner" ]] || fail "package manager owns source manifest path ($manifest_owner)"
    echo "Staged ${#files[@]} files before modifying $PREFIX."
    for i in "${!files[@]}"; do
        rel=${rels[$i]}; dest="$PREFIX/$rel"; mkdir -p -- "$(dirname -- "$dest")"
        tmp=$(mktemp "${dest}.baradwatchu.XXXXXX")
        if ! install -m 0644 "${files[$i]}" "$tmp"; then unlink -- "$tmp"; fail "could not stage destination file: $dest"; fi
        [[ "$rel" == "bin/$BIN" ]] && chmod 0755 "$tmp"
        if ! mv -f -- "$tmp" "$dest"; then unlink -- "$tmp"; fail "could not replace destination file: $dest"; fi
        unset 'old[$rel]'
    done
    for rel in "${!old[@]}"; do [[ ! -e "$PREFIX/$rel" ]] || unlink -- "$PREFIX/$rel"; done
    mkdir -p -- "$(dirname -- "$manifest")"; tmp=$(mktemp "${manifest}.baradwatchu.XXXXXX")
    { printf 'BaradWatchU source manifest v1\nclient\n%s\n%s\n' "$PREFIX" "$VERSION"; cat "$stage/manifest-entries"; } > "$stage/final-manifest"
    if ! install -m 0644 "$stage/final-manifest" "$tmp"; then unlink -- "$tmp"; fail 'could not stage source manifest'; fi
    if ! mv -f -- "$tmp" "$manifest"; then unlink -- "$tmp"; fail 'could not replace source manifest'; fi
    echo "Installed BaradWatchU Client $VERSION. No packages/services were changed; configuration and user data were preserved."
}

while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0;; -V|--version) echo "BaradWatchU Client $VERSION"; exit 0;;
        --missing-deps) MISSING=1;; --dry-run) DRY=1;; --no-build) NO_BUILD=1;; --build-only) BUILD_ONLY=1;; --local) LOCAL=1;; -U|--uninstall) UNINSTALL=1;;
        --prefix=*) PREFIX=${1#*=}; PREFIX_SET=1;; --prefix) shift; (($#))||badarg '--prefix requires DIR'; PREFIX=$1; PREFIX_SET=1;;
        --build-dir=*) BUILD_DIR=${1#*=}; BUILD_SET=1;; --build-dir) shift; (($#))||badarg '--build-dir requires DIR'; BUILD_DIR=$1; BUILD_SET=1;;
        *) badarg "unknown option: $1";;
    esac
    shift
done
if ((MISSING)); then ((DRY+NO_BUILD+BUILD_ONLY+LOCAL+UNINSTALL+PREFIX_SET+BUILD_SET==0))||badarg '--missing-deps conflicts with other options'; deps && exit 0 || exit 1; fi
((BUILD_ONLY==0||DRY==0&&NO_BUILD==0&&LOCAL==0&&UNINSTALL==0&&PREFIX_SET==0))||badarg '--build-only conflicts with install options'
((BUILD_ONLY==0||BUILD_SET==1))||badarg '--build-only requires explicit --build-dir=DIR'
((LOCAL==0||PREFIX_SET==0))||badarg '--local conflicts with --prefix'
((UNINSTALL==0||NO_BUILD==0&&BUILD_SET==0))||badarg '--uninstall conflicts with build options'
if ((LOCAL)); then [[ "$EUID" != 0 && -n "${HOME:-}" ]]||fail '--local requires a non-root user with HOME'; PREFIX="$HOME/.local"; fi
[[ "$PREFIX" == /* && "$PREFIX" != / ]]||badarg '--prefix must be absolute and may not be /'
PREFIX=$(canonical "$PREFIX"); BUILD_DIR=$(canonical "$BUILD_DIR")
case "$BUILD_DIR/" in "$ROOT/"*) badarg '--build-dir must be outside source tree';; esac
manifest="$PREFIX/share/baradwatchu-source/$BIN.manifest"
if ((BUILD_ONLY)); then build; echo "Build-only complete; validated cache at $BUILD_DIR. No prefix files or services changed."; exit 0; fi
if ((UNINSTALL)); then ((DRY))&&echo 'Dry-run: no files/services change.'; uninstall; exit 0; fi
if ((DRY)); then
    echo "BaradWatchU Client $VERSION; prefix=$PREFIX; build-dir=$BUILD_DIR"
    ((LOCAL))&&echo 'User-local development only; no service or privileged auditing.'||echo 'System files only; no service is configured.'
    echo "Binary=$PREFIX/bin/$BIN; Angular=$PREFIX/share/baradwatchu-client/web; manifest=$manifest"
    echo 'Configuration/data remain untouched; service action: none.'; deps||echo 'Dry-run blocked for a real build by missing dependencies; no changes made.'
    if ((NO_BUILD)); then validate_build; else echo 'Plan: build unprivileged, stage artifacts, install manifest-owned files.'; fi
    echo 'Dry-run complete; no files or services changed.'; exit 0
fi
install_source
