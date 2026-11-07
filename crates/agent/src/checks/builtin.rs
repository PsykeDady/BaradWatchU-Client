//! Built-in metadata and applicability; native observations are delegated to platform adapters.
use crate::{
    audit::{
        self, AuditReport, Check, CheckMetadata, Clock, Evidence, OperatingSystem, Outcome, Reason,
        Status,
    },
    platform::{command::ProbeError, AuditPlatform},
};
use serde_json::json;

#[derive(Clone, Copy)]
enum Kind {
    Identity,
    Updates,
    Encryption,
    ScreenLock,
    PasswordAging,
    PasswordWarning,
    PasswordComplexity,
    Tpm,
    SecureBoot,
    Firewall,
    HomeEncryption,
    SensitiveEncryption,
    SwapProtection,
    EncryptionDiscovery,
}

/// Single observation entry point for shipped script wrappers; never a compliance verdict.
pub fn observe_one(platform: &dyn AuditPlatform, id: &str) -> Outcome {
    let kind = match id {
        "SEC-001" => Kind::Updates,
        "SEC-006" => Kind::Encryption,
        "SEC-007" => Kind::ScreenLock,
        "SEC-008" => Kind::PasswordAging,
        "SEC-009" => Kind::PasswordWarning,
        "SEC-010" => Kind::PasswordComplexity,
        "SEC-012" => Kind::Tpm,
        "SEC-013" => Kind::SecureBoot,
        "SEC-014" => Kind::Firewall,
        "SEC-015" => Kind::HomeEncryption,
        "SEC-017" => Kind::SwapProtection,
        _ => {
            return Outcome::new(
                Status::Warn,
                Reason::EvidenceInconclusive,
                "This single observation requires an audit policy with explicit target scope",
            )
        }
    };
    Builtin {
        kind,
        platform,
        os: &platform.operating_system(),
        policy: None,
        aging: &std::cell::OnceCell::new(),
    }
    .evaluate()
}
struct Builtin<'a> {
    kind: Kind,
    platform: &'a dyn AuditPlatform,
    os: &'a Result<OperatingSystem, ProbeError>,
    policy: Option<&'a crate::policy::Policy>,
    aging: &'a std::cell::OnceCell<Outcome>,
}

impl Check for Builtin<'_> {
    fn metadata(&self) -> CheckMetadata {
        let (id, name, description) = match self.kind {
            Kind::Identity => ("SYS-OS-001", "Operating system identity", "Identify distribution/version from os-release; not a support-lifecycle certification"),
            Kind::Updates => ("SEC-001", "Pending system updates", "Inspect Fedora DNF5 or Arch pacman cached update availability; does not implement the future 90-day policy"),
            Kind::Encryption => ("SEC-006", "Root filesystem encryption", "Trace root backing devices to active LUKS/dm-crypt; other filesystems and key strength are outside scope"),
            Kind::ScreenLock => ("SEC-007", "Automatic screen-lock security", "Observe a single current-user Plasma 6 Wayland session and resolved password-lock configuration"),
            Kind::PasswordAging => ("SEC-008", "Local password aging", "Observe effective aging for ordinary local interactive accounts; creation defaults are separate"),
            Kind::PasswordWarning => ("SEC-009", "Password expiry warning", "Observe effective account warning periods; no directory/IdP claim"),
            Kind::PasswordComplexity => ("SEC-010", "Password complexity", "Observe configured password-quality requirements and application evidence; platform mechanism belongs to the adapter"),
            Kind::Tpm => ("SEC-012", "TPM 2.0 presence and accessibility", "Observe cached kernel TPM version, device identity and read permission without TPM operations"),
            Kind::SecureBoot => ("SEC-013", "UEFI Secure Boot", "Observe SecureBoot and SetupMode EFI variables; no independent boot-chain or module trust claim"),
            Kind::Firewall => ("SEC-014", "Host firewall", "Separate manager service state from provable Netfilter INPUT filtering on IPv4 and IPv6"),
            Kind::HomeEncryption => ("SEC-015", "Home encryption", "Inspect the current user's home mount and backing encryption"),
            Kind::SensitiveEncryption => ("SEC-016", "Sensitive paths encryption", "Inspect only policy-authorized path coverage"),
            Kind::SwapProtection => ("SEC-017", "Swap protection", "Inspect all active swap devices and files"),
            Kind::EncryptionDiscovery => ("SYS-ENC-001", "Encrypted mount discovery", "List counts of observed encrypted mount technologies; not a compliance check"),
        };
        CheckMetadata {
            id: id.to_owned(),
            name: name.to_owned(),
            description: description.to_owned(),
            version: if matches!(self.kind, Kind::ScreenLock) {
                "1.1.1"
            } else if matches!(self.kind, Kind::Updates) {
                "1.2.1"
            } else if matches!(self.kind, Kind::Encryption) {
                "1.2.0"
            } else {
                "1.0.0"
            }
            .to_owned(),
        }
    }
    fn evaluate(&self) -> Outcome {
        let os = match self.os {
            Ok(os) => os,
            Err(error) => {
                return Outcome::new(
                    Status::Error,
                    if matches!(self.kind, Kind::Identity) {
                        error.reason
                    } else {
                        Reason::OsIdentityUnavailable
                    },
                    error.message.clone(),
                )
                .with_evidence(Evidence::new(
                    "OS identity prerequisite",
                    "platform applicability",
                    &[],
                ))
            }
        };
        if matches!(self.kind, Kind::Identity) {
            return Outcome::new(if os.distribution_id.is_some() { Status::Pass } else { Status::Warn },
                if os.distribution_id.is_some() { Reason::OsIdentified } else { Reason::UnsupportedPlatform },
                "OS identity is observational; support and security compliance are reported separately")
                .with_evidence(Evidence::new(os.identity_source.as_deref().unwrap_or("compile-time OS target"), "OS identity only", &[
                    ("distributionId", json!(os.distribution_id)), ("name", json!(os.name)),
                    ("versionId", json!(os.version_id)), ("variantId", json!(os.variant_id)),
                    ("fedoraChecksApplicable", json!(os.supported && os.distribution_id.as_deref() == Some("fedora"))),
                    ("archChecksApplicable", json!(os.supported && os.distribution_id.as_deref() == Some("arch"))),
                ]));
        }
        if !os.supported {
            return Outcome::new(
                Status::NotApplicable,
                Reason::UnsupportedPlatform,
                os.support_reason.clone(),
            )
            .with_evidence(Evidence::new(
                "OS identity prerequisite",
                "Native Arch Linux / Fedora RPM/DNF5 checks",
                &[
                    ("distributionId", json!(os.distribution_id)),
                    ("variantId", json!(os.variant_id)),
                ],
            ));
        }
        match self.kind {
            Kind::Updates => self.platform.pending_updates(),
            Kind::Encryption => self.platform.root_encryption(),
            Kind::ScreenLock => self.platform.screen_lock(),
            Kind::PasswordAging | Kind::PasswordWarning => self
                .aging
                .get_or_init(|| self.platform.password_aging())
                .clone(),
            Kind::PasswordComplexity => self.platform.password_complexity(),
            Kind::Tpm => self.platform.tpm(),
            Kind::SecureBoot => self.platform.secure_boot(),
            Kind::Firewall => self.platform.firewall(),
            Kind::HomeEncryption => self.platform.home_encryption(),
            Kind::SensitiveEncryption => self.platform.sensitive_encryption(
                &self
                    .policy
                    .and_then(|p| p.checks.sensitive_encryption.as_ref())
                    .expect("enabled policy")
                    .targets,
            ),
            Kind::SwapProtection => self.platform.swap_protection(),
            Kind::EncryptionDiscovery => self.platform.encryption_discovery(),
            Kind::Identity => unreachable!(),
        }
    }
}

pub fn standalone(platform: &dyn AuditPlatform, clock: &dyn Clock) -> Result<AuditReport, String> {
    collect(platform, clock, true, true, None)
}

pub fn standalone_with_policy(
    platform: &dyn AuditPlatform,
    clock: &dyn Clock,
    policy: &crate::policy::Policy,
) -> Result<AuditReport, String> {
    standalone_with_local_config(platform, clock, policy, None)
}

pub fn standalone_with_local_config(
    platform: &dyn AuditPlatform,
    clock: &dyn Clock,
    policy: &crate::policy::Policy,
    local: Option<&crate::local_config::LocalConfig>,
) -> Result<AuditReport, String> {
    policy.validate()?;
    let effective = match local {
        Some(config) => config.effective_policy(policy)?,
        None => policy.clone(),
    };
    let mut report = collect(
        platform,
        clock,
        effective.checks.updates.enabled,
        effective.checks.encryption.enabled,
        Some(&effective),
    )?;
    if policy.schema_version == crate::policy::POLICY_SCHEMA_V3 {
        report.schema_version = "baradwatchu.audit-report.v2".into();
    }
    let mut evaluation = crate::policy::evaluate(&effective, &report)?;
    if let Some(config) = local {
        evaluation.policy = policy.redacted_for_report();
        evaluation.local_monitoring = Some(crate::policy::LocalMonitoringSummary {
            target_ids: config
                .sensitive_targets
                .iter()
                .map(|t| t.id.clone())
                .collect(),
        });
    }
    report.policy_evaluation = Some(evaluation);
    Ok(report)
}

fn collect(
    platform: &dyn AuditPlatform,
    clock: &dyn Clock,
    updates_enabled: bool,
    encryption_enabled: bool,
    policy: Option<&crate::policy::Policy>,
) -> Result<AuditReport, String> {
    let os = platform.operating_system();
    let aging = std::cell::OnceCell::new();
    let identity = Builtin {
        kind: Kind::Identity,
        platform,
        os: &os,
        policy,
        aging: &aging,
    };
    let updates = Builtin {
        kind: Kind::Updates,
        platform,
        os: &os,
        policy,
        aging: &aging,
    };
    let encryption = Builtin {
        kind: Kind::Encryption,
        platform,
        os: &os,
        policy,
        aging: &aging,
    };
    let report_os = os
        .clone()
        .unwrap_or_else(|_| OperatingSystem::unidentified(std::env::consts::OS));
    let mut checks: Vec<&dyn Check> = vec![&identity];
    if updates_enabled {
        checks.push(&updates);
    }
    if encryption_enabled {
        checks.push(&encryption);
    }
    let mut extra: Vec<_> = [
        ("SEC-007", Kind::ScreenLock),
        ("SEC-008", Kind::PasswordAging),
        ("SEC-009", Kind::PasswordWarning),
        ("SEC-010", Kind::PasswordComplexity),
        ("SEC-012", Kind::Tpm),
        ("SEC-013", Kind::SecureBoot),
        ("SEC-014", Kind::Firewall),
        ("SEC-015", Kind::HomeEncryption),
        ("SEC-016", Kind::SensitiveEncryption),
        ("SEC-017", Kind::SwapProtection),
    ]
    .into_iter()
    .filter(|(id, _)| policy.is_some_and(|p| p.enabled(id)))
    .map(|(_, kind)| Builtin {
        kind,
        platform,
        os: &os,
        policy,
        aging: &aging,
    })
    .collect();
    if policy.is_some_and(|p| p.schema_version == crate::policy::POLICY_SCHEMA_V3) {
        extra.push(Builtin {
            kind: Kind::EncryptionDiscovery,
            platform,
            os: &os,
            policy,
            aging: &aging,
        });
    }
    for check in &extra {
        checks.push(check)
    }
    audit::run(report_os, &checks, clock)
}
