#!/usr/bin/env bash
set -Eeuo pipefail
PRODUCT=Client BIN=baradwatchu-agent
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
VERSION=$(awk '/^[[:space:]]*\[workspace[.]package\]/{f=1;next} /^[[:space:]]*\[/{f=0} f&&/^[[:space:]]*version[[:space:]]*=/{split($0,a,"\"");print a[2];exit}' "$ROOT/Cargo.toml")
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo 'Invalid SemVer in Cargo.toml' >&2; exit 1; }
PREFIX=/usr/local BUILD_DIR=${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/baradwatchu/$BIN-$VERSION
LOCAL=0 UNINSTALL=0 DRY=0 NO_BUILD=0 BUILD_ONLY=0 MISSING=0 PREFIX_SET=0 BUILD_SET=0
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
        *' arch '*) family=Arch; suggest='sudo pacman -S --needed base-devel python rust nodejs npm' ;;
        *' fedora '*|*' rhel '*) family=Fedora; suggest='sudo dnf install gcc gcc-c++ make python3 tar rust cargo nodejs npm' ;;
        *' debian '*|*' ubuntu '*) family=Debian/Ubuntu; suggest='sudo apt update && sudo apt install build-essential python3 tar cargo rustc nodejs npm' ;;
    esac
    echo "Dependency audit: Client $VERSION ($family)"
    if command -v rustc >/dev/null && rv=$(rustc --version|awk '{print $2}') && ge "$rv" 1.80.0; then echo "[ok] rustc $rv"; else echo '[missing] rustc >=1.80.0'; missing=1; fi
    if command -v cargo >/dev/null && cv=$(cargo --version|awk '{print $2}') && ge "$cv" 1.80.0; then echo "[ok] Cargo $cv"; else echo '[missing] Cargo >=1.80.0'; missing=1; fi
    if command -v node >/dev/null && nv=$(node -p 'process.versions.node') && [[ "$nv" == 20.* ]] && ge "$nv" 20.11.1; then echo "[ok] Node.js $nv"; else echo '[missing] Node.js 20 >=20.11.1 (run nvm use in web/)'; missing=1; fi
    if command -v npm >/dev/null && np=$(npm --version) && ge "$np" 8.0.0; then echo "[ok] npm $np"; else echo '[missing] npm >=8.0.0'; missing=1; fi
    for tool in cc c++ make python3 tar; do
        if command -v "$tool" >/dev/null; then echo "[ok] $tool"; else echo "[missing] build tool: $tool"; missing=1; fi
    done
    libc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
    if [[ "$libc" == glibc\ * ]] && ge "${libc#glibc }" 2.17.0; then echo "[ok] $libc build host (cache records this version)"; else echo '[missing] glibc >=2.17 runtime'; missing=1; fi
    if [[ -x "$ROOT/web/node_modules/.bin/ng" && -d "$ROOT/web/node_modules/@angular-devkit/build-angular" ]]; then
        echo '[ok] local Angular builder dependencies'
    else
        echo '[missing project dependencies] Angular builder packages (source build installs these in its isolated cache with npm ci)'
        project_missing=1
    fi
    echo 'Optional dependencies:'
    for tool in systemctl xdg-open shellcheck; do if command -v "$tool" >/dev/null; then echo "  [optional present] $tool"; else echo "  [optional absent] $tool"; fi; done
    echo '  systemctl service integration and xdg-open viewer launch are deferred.'
    if (( missing )); then
        [[ -z "$suggest" ]] || echo "Suggested package command: $suggest"
        (( project_missing == 0 )) || echo "Suggested project command: (cd '$ROOT/web' && npm ci --no-audit --no-fund)"
        echo 'Select Node.js 20 >=20.11.1 using web/.nvmrc and npm >=8.0.0; if using nvm, run nvm use in web/.'
        [[ -n "$suggest" ]] || echo 'No package command suggested for this distribution family.'
        return 1
    fi
    if (( project_missing )) && [[ "$mode" == audit ]]; then
        echo "Suggested project command: (cd '$ROOT/web' && npm ci --no-audit --no-fund)"
        return 1
    fi
    (( project_missing == 0 )) || echo 'Angular packages will be installed in the build cache; a --no-build install does not need them.'
    return 0
}

canonical() { realpath -m -- "$1"; }
prefix_writable() { local p="$PREFIX"; (( EUID == 0 )) && return 0; while [[ ! -e "$p" ]]; do p=$(dirname -- "$p"); done; [[ -d "$p" && -w "$p" && -x "$p" ]]; }
fingerprint() {
    (cd "$ROOT"; local paths=(Cargo.toml install.sh crates web); [[ ! -f Cargo.lock ]] || paths+=(Cargo.lock); [[ ! -d .cargo ]] || paths+=(.cargo); find "${paths[@]}" -type d \( -name .git -o -name target -o -name node_modules -o -name dist -o -name .angular -o -name out-tsc \) -prune -o \( -type f -o -type l \) -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
}
web_ok() {
    local pv av lv
    pv=$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([0-9.]*\)".*/\1/p' "$ROOT/web/package.json"|head -1)
    av=$(sed -n "s/^export const APP_VERSION = '\([^']*\)';$/\1/p" "$ROOT/web/src/app-version.ts")
    lv=$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([0-9.]*\)".*/\1/p' "$ROOT/web/package-lock.json"|head -1)
    [[ "$pv" == "$VERSION" && "$av" == "$VERSION" && "$lv" == "$VERSION" ]]
}
mvget() { sed -n "s/^$1=//p" "$2"|head -1; }
artifact_fingerprint() {
    (cd "$BUILD_DIR"; { printf '%s\0' "cargo-target/release/$BIN"; find angular/browser -type f -print0; } | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
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
    [[ -s "$BUILD_DIR/angular/browser/index.html" ]] || fail 'Angular assets incomplete'
    [[ -n "$(find "$BUILD_DIR/angular/browser" -type f -name '*.js' -print -quit)" ]] || fail 'Angular JavaScript bundle missing'
    [[ ! -L "$BUILD_DIR/angular" && ! -L "$BUILD_DIR/angular/browser" && -z "$(find "$BUILD_DIR/angular/browser" -type l -print -quit)" ]] || fail 'symlinks are not allowed in built web assets'
    [[ $(mvget artifacts "$m") == "$(artifact_fingerprint)" ]] || fail 'cached artifacts changed; rebuild with --build-only'
    echo "Validated build $BUILD_DIR ($platform, $VERSION)"
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
    deps build || fail 'required system build dependencies are missing'
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
    # Preflight every owned path before removing any of them, so a modified
    # later entry cannot cause a partially completed uninstall.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue; IFS=$'\t' read -r k h p <<< "$line"; path="$PREFIX/$p"
        parent=$(canonical "$(dirname -- "$path")"); [[ "$parent" == "$PREFIX"/* ]] || fail "manifest path escapes prefix: $path"
        o=$(owner "$path"); [[ -z "$o" ]] || fail "package manager owns $path ($o)"
        if [[ -e "$path" || -L "$path" ]]; then hash_ok "$path" "$h" || fail "changed file preserved: $path"; fi
    done < <(tail -n +5 "$manifest")
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
    prefix_writable || fail "prefix is not writable; run --build-only as user, then sudo ./install.sh --no-build --build-dir='$BUILD_DIR' --prefix='$PREFIX'"
    if ((NO_BUILD)); then validate_build; else build; fi
    STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/baradwatchu-client-stage.XXXXXX")
    install -D -m 0755 "$BUILD_DIR/cargo-target/release/$BIN" "$STAGE_DIR/bin/$BIN"
    mkdir -p "$STAGE_DIR/$app"; cp -a "$BUILD_DIR/angular/browser/." "$STAGE_DIR/$app/"
    : > "$STAGE_DIR/manifest-entries"
    if [[ -e "$manifest" || -L "$manifest" ]]; then
        load_manifest
        while IFS= read -r line; do [[ -z "$line" ]] && continue; IFS=$'\t' read -r _ h rel <<< "$line"; old["$rel"]=$h; done < <(tail -n +5 "$manifest")
    fi
    while IFS= read -r -d '' path; do
        rel=${path#"$STAGE_DIR"/}; allowed "$rel" || fail "staged path outside allowed destinations: $rel"
        dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "destination escapes prefix: $dest"
        o=$(owner "$dest"); [[ -z "$o" ]] || fail "package manager owns $dest ($o)"
        if [[ -e "$dest" || -L "$dest" ]]; then [[ -n "${old[$rel]:-}" ]] || fail "unmanaged file exists: $dest"; hash_ok "$dest" "${old[$rel]}" || fail "changed file preserved: $dest"; fi
        h=$(sha256sum -- "$path"|awk '{print $1}'); printf 'file\t%s\t%s\n' "$h" "$rel" >> "$STAGE_DIR/manifest-entries"; files+=("$path"); rels+=("$rel")
    done < <(find "$STAGE_DIR/bin" "$STAGE_DIR/$app" -type f -print0)
    for rel in "${!old[@]}"; do
        local present=0; for path in "${rels[@]}"; do [[ "$path" == "$rel" ]] && present=1; done
        ((present)) && continue; dest="$PREFIX/$rel"; parent=$(canonical "$(dirname -- "$dest")"); [[ "$parent" == "$PREFIX"/* ]] || fail "old manifest path escapes prefix: $dest"; o=$(owner "$dest"); [[ -z "$o" ]] || fail "package manager owns $dest"; if [[ -e "$dest" || -L "$dest" ]]; then hash_ok "$dest" "${old[$rel]}" || fail "changed old file preserved: $dest"; fi
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
    { printf 'BaradWatchU source manifest v1\nclient\n%s\n%s\n' "$PREFIX" "$VERSION"; cat "$STAGE_DIR/manifest-entries"; } > "$STAGE_DIR/final-manifest"
    if ! install -m 0644 "$STAGE_DIR/final-manifest" "$tmp"; then unlink -- "$tmp"; fail 'could not stage source manifest'; fi
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
[[ -n "$BUILD_DIR" && "$PREFIX$BUILD_DIR" != *$'\n'* && "$PREFIX$BUILD_DIR" != *$'\r'* && "$PREFIX$BUILD_DIR" != *$'\t'* ]] || badarg 'paths must be non-empty and contain no tabs or newlines'
PREFIX=$(canonical "$PREFIX"); BUILD_DIR=$(canonical "$BUILD_DIR")
[[ "$PREFIX" != / ]] || badarg '--prefix resolves to /; choose a dedicated prefix'
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
