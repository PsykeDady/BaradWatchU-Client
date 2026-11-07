# Shipped workstation collectors

Universal adapter MVP supersedes the original SEC-011 execution path described below: normal workstation execution now uses the actual file `../adapters/SEC-011.sh` and the versioned external evidence contract. This directory retains the original embedded compatibility source. See [the contributor guide](../../docs/check-adapters.md); SEC-003/004 remain embedded and native wrappers remain unchanged.

Use `baradwatchu-agent workstation list` and the opt-in workstation policy from the repository README/LEGGIMI. Run audits through the agent, not by executing collector bodies directly: the agent installs the read-only guard, validates output and discards diagnostics. Script source changes require rebuilding the agent; editing an installed `.sh` does not change its embedded collectors.

| ID | Implementation / scope |
| --- | --- |
| SEC-001 | Rust wrapper: cached package updates, no refresh |
| SEC-003 | Embedded Bash: ClamAV services, candidate prevention setting/signature mtime |
| SEC-004 | Embedded Bash: hosts sink counts, candidate dnsmasq rules, resolver/NSS indicators |
| SEC-006 | Rust wrapper: root encryption |
| SEC-007 | Rust wrapper: supported desktop lock configuration |
| SEC-008 | Rust wrapper: effective local account aging |
| SEC-009 | Rust wrapper: effective expiry warning |
| SEC-010 | Rust wrapper: configured PAM quality enforcement |
| SEC-011 | Embedded Bash: Cato-reported status only; optional in example |
| SEC-012 | Rust wrapper: TPM presence/accessibility |
| SEC-013 | Rust wrapper: Secure Boot |
| SEC-014 | Rust wrapper: host firewall |
| SEC-015 | Rust wrapper: home encryption |
| SEC-016 | Policy-scoped sensitive targets; single observation returns inconclusive |
| SEC-017 | Rust wrapper: swap protection |

Native wrappers accept one explicit absolute trusted agent path, for example `bash scripts/audit/SEC-008.sh /absolute/path/baradwatchu-agent`. This runs a diagnostic observation, not a policy evaluation; exit4 is intentional. Audit selection only applies to `workstation audit`, not manually requested diagnostics.

Only the three supplemental collectors are executed as Bash by Rust. Other IDs stay in-process in the tested native adapters during an audit, avoiding nested sandbox constraints and duplicated logic. No externally registered script execution or remote executable distribution is implemented.

Reference scope: audit-postazione skill; kdetraycato status tokens (not recovery); install-dnsmasq-hagezi.sh inspection ideas (not installation, self-test or DNS queries); RicordatiCheDeviCambiare aging approach (no notifier/state writes). The existing CP5 account/PAM adapters retain their stronger evidence handling. The pack does not regenerate personal skill reports.
