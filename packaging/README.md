# Client distribution plan

Status: package channels remain planning only. The source installer was exercised in an isolated prefix using built release outputs, including update and uninstall; its `--build-only` Rust stage passes but the fresh npm install is blocked by unavailable offline dependencies in this environment. Cache v2 records source and artifact digests plus build-host glibc; it does not execute cached binaries during install. No native package artifact, service unit, Windows setup executable or macOS DMG has been built or tested, and no distribution channel is claimed as supported.

## Shared build and ownership model

`Cargo.toml` supplies the product version. A release build produces the Rust agent executable plus Angular browser assets under the installer's marked build cache. Future packaging recipes consume that staged payload; they do not rebuild it independently. The local Angular viewer remains separate from the background agent.

`product.toml` records target formats, paths, privileges and ownership without duplicating the version. It is planning metadata, not an installer recipe.

| Channel | Planned payload / ownership | Configuration and data | Service / privileges |
|---|---|---|---|
| Source | `bin/baradwatchu-agent`, `bin/baradwatchu-tray` (unless `--without-tray`), `share/applications/baradwatchu-tray.desktop`, `share/baradwatchu-client/web`; source manifest owns only unchanged listed files | Preserve user identities, trust stores, settings, history and `/var/lib/baradwatchu` (service registrations); source installer creates none | System mode (root-owned prefix): systemd unit `baradwatchu-agent.service` always installed/updated by `install.sh` through `packaging/service/install-service.sh` in the sudo step; uninstall removes it. Per-user mode (`--local` or user-writable prefix): no service, no remote communication; local features complete |
| Arch `pacman` | `/usr/bin/baradwatchu-agent`, `/usr/share/baradwatchu-client/web`; PKGBUILD/pacman owns files | `/etc/baradwatchu/client`, `/var/lib/baradwatchu/client`; preserve enrollment identity and audit data | Future systemd system service, installed/enabled only by explicit package/operator policy; no privileged helper in this checkpoint |
| Debian/Ubuntu `.deb` | `/usr/bin`, `/usr/share/baradwatchu-client`; dpkg owns files | `/etc` conffiles and `/var/lib`; uninstall preserves device identity and audit history | Future unit; no implicit start/restart from package scripts |
| Fedora `.rpm` | `/usr/bin`, `/usr/share/baradwatchu-client`; rpm owns files | `/etc` and `/var/lib`; preserve data on update/erase | Future unit; service state changes require explicit policy |
| Windows `setup.exe` | Planned WiX Burn bundle around a signed client package; Windows Installer owns binaries | `%ProgramData%\BaradWatchU\Client` for machine config/state; preserve on uninstall unless a reviewed decommission flow explicitly removes identity | Administrator approval to register a Windows Service; Authenticode signing required; no arbitrary privileged helper |
| macOS `.dmg` | Planned DMG containing a signed/notarized installer package and local viewer | `/Library/Application Support/BaradWatchU/Client`; preserve identity and audit data on uninstall | Admin-authorized `launchd` LaunchDaemon; Developer ID signing and notarization required; no helper until separately reviewed |

The tray companion is a per-user desktop-session process, never a system service: packages may ship its binary and menu entry, but start at login stays a per-user choice (XDG autostart, `HKCU\…\Run`, per-user LaunchAgent). Its Windows/macOS code is compile-checked only.

Current Windows setup (before the planned WiX bundle): `install.ps1 -Package` compiles `packaging/windows/baradwatchu-client.iss` (Inno Setup 6); all users by default (system mode: administrator, Program Files, Windows service always installed through `packaging/service/install-service.ps1`) or only for me (per-user mode, no service) (stop before files, verified restart, removal on uninstall, data kept). Not compiled or run on Windows yet. macOS has no Client installer: `packaging/service/install-service.sh` is run by hand there.

Package-manager installs must refuse source-installer overwrite/uninstall. Source uninstall uses its own hash manifest and leaves config/data. Windows/macOS installers must remove only package-owned files and preserve machine identity by default.

## Deferred release work

Add PKGBUILD, Debian metadata, RPM spec and systemd unit after Linux service lifecycle is reviewed. Build Windows `setup.exe` only with service registration, signing and isolated install/upgrade/uninstall tests. Build a signed/notarized DMG only with LaunchDaemon lifecycle and data-preservation tests. No channel is considered supported until its actual artifact passes clean-machine validation.
