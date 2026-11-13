#!/usr/bin/bash
# Regenerate catalog/builtin-tools.sha256: one line per file of every built-in check folder
# ("<ID> <platform> catalog/<dir>/<ID>/<file> <sha256>"), for Linux (catalog/checks), Windows
# (catalog/checks-windows) and macOS (catalog/checks-macos). The manifest is embedded in the
# agent at build time and every audit re-hashes the installed files against it. Run after
# editing any built-in check file (on macOS: bash scripts/update-builtin-hashes.sh).
# Entry-point checks also get their configuration.json "expectedSha256" refreshed first, so the
# configuration hash in the manifest covers the final file. Custom checks are never listed.
set -euo pipefail
root=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)
exec /usr/bin/python3 -I - "$root" <<'EOF'
import hashlib, json, pathlib, re, sys

root = pathlib.Path(sys.argv[1])
catalog = root / "catalog"
lines = []
for directory, platform in (("checks", "linux"), ("checks-windows", "windows"), ("checks-macos", "macos")):
    base = catalog / directory
    for folder in sorted(p for p in base.iterdir() if p.is_dir()):
        config_path = folder / "configuration.json"
        raw = config_path.read_bytes()
        config = json.loads(raw)
        if config.get("id") != folder.name:
            sys.exit(f"{config_path}: id differs from folder name")
        tool = config.get("toolPath")
        if tool:
            digest = hashlib.sha256((folder / tool).read_bytes()).hexdigest()
            text = raw.decode("utf-8")
            updated, count = re.subn(r'("expectedSha256"\s*:\s*")[0-9a-f]{64}(")', rf"\g<1>{digest}\g<2>", text)
            if count != 1:
                sys.exit(f"{config_path}: expected exactly one expectedSha256 entry")
            if updated != text:
                config_path.write_bytes(updated.encode("utf-8"))
        elif "expectedSha256" in config:
            sys.exit(f"{config_path}: provider-based checks must not declare expectedSha256")
        for path in sorted(p for p in folder.rglob("*")):
            if path.is_symlink():
                sys.exit(f"{path}: symbolic links are not allowed")
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                lines.append(f"{folder.name} {platform} {relative} {hashlib.sha256(path.read_bytes()).hexdigest()}")
(catalog / "builtin-tools.sha256").write_text("\n".join(lines) + "\n", encoding="ascii")
print(f"{len(lines)} file in catalog/builtin-tools.sha256")
EOF
