# Client distribution plan

Status: planning only. Source-installer code exists at `../install.sh`, but an end-to-end release installation is unverified; no distribution channel is claimed as supported. No package artifact, service unit, Windows setup executable or macOS DMG has been built or tested.

## Shared build and ownership model

`Cargo.toml` supplies the product version. A release build produces the Rust agent executable plus Angular browser assets under the installer's marked build cache. Future packaging recipes consume that staged payload; they do not rebuild it independently. The local Angular viewer remains separate from the background agent.

`product.toml` records target formats, paths, privileges and ownership without duplicating the version. It is planning metadata, not an installer recipe.

| Channel | Planned payload / ownership | Configuration and data | Service / privileges |
|---|---|---|---|
| Source | `bin/baradwatchu-agent`, `share/baradwatchu-client/web`; source manifest owns only unchanged listed files | Preserve `/etc/baradwatchu/client`, `/var/lib/baradwatchu/client` and custom-check data; source installer creates none | No service/helper yet. User-local install is development-only and offers no system auditing |
| Arch `pacman` | `/usr/bin/baradwatchu-agent`, `/usr/share/baradwatchu-client/web`; PKGBUILD/pacman owns files | `/etc/baradwatchu/client`, `/var/lib/baradwatchu/client`; preserve enrollment identity and audit data | Future systemd system service, installed/enabled only by explicit package/operator policy; no privileged helper in this checkpoint |
| Debian/Ubuntu `.deb` | `/usr/bin`, `/usr/share/baradwatchu-client`; dpkg owns files | `/etc` conffiles and `/var/lib`; uninstall preserves device identity and audit history | Future unit; no implicit start/restart from package scripts |
| Fedora `.rpm` | `/usr/bin`, `/usr/share/baradwatchu-client`; rpm owns files | `/etc` and `/var/lib`; preserve data on update/erase | Future unit; service state changes require explicit policy |
| Windows `setup.exe` | Planned WiX Burn bundle around a signed client package; Windows Installer owns binaries | `%ProgramData%\BaradWatchU\Client` for machine config/state; preserve on uninstall unless a reviewed decommission flow explicitly removes identity | Administrator approval to register a Windows Service; Authenticode signing required; no arbitrary privileged helper |
| macOS `.dmg` | Planned DMG containing a signed/notarized installer package and local viewer | `/Library/Application Support/BaradWatchU/Client`; preserve identity and audit data on uninstall | Admin-authorized `launchd` LaunchDaemon; Developer ID signing and notarization required; no helper until separately reviewed |

Package-manager installs must refuse source-installer overwrite/uninstall. Source uninstall uses its own hash manifest and leaves config/data. Windows/macOS installers must remove only package-owned files and preserve machine identity by default.

## Deferred release work

Add PKGBUILD, Debian metadata, RPM spec and systemd unit after Linux service lifecycle is reviewed. Build Windows `setup.exe` only with service registration, signing and isolated install/upgrade/uninstall tests. Build a signed/notarized DMG only with LaunchDaemon lifecycle and data-preservation tests. No channel is considered supported until its actual artifact passes clean-machine validation.
