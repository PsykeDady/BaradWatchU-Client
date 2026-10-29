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
}
struct Builtin<'a> {
    kind: Kind,
    platform: &'a dyn AuditPlatform,
    os: &'a Result<OperatingSystem, ProbeError>,
}

impl Check for Builtin<'_> {
    fn metadata(&self) -> CheckMetadata {
        let (id, name, description) = match self.kind {
            Kind::Identity => ("SYS-OS-001", "Operating system identity", "Identify distribution/version from os-release; not a support-lifecycle certification"),
            Kind::Updates => ("SEC-001", "Pending system updates", "Inspect Fedora DNF5 cached update availability; does not implement the future 90-day policy"),
            Kind::Encryption => ("SEC-006", "Root filesystem encryption", "Trace root backing devices to active LUKS/dm-crypt; other filesystems and key strength are outside scope"),
        };
        CheckMetadata {
            id: id.to_owned(),
            name: name.to_owned(),
            description: description.to_owned(),
            version: "1.0.0".to_owned(),
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
                    ("fedoraChecksApplicable", json!(os.supported)),
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
                "Fedora RPM/DNF5 checks",
                &[
                    ("distributionId", json!(os.distribution_id)),
                    ("variantId", json!(os.variant_id)),
                ],
            ));
        }
        match self.kind {
            Kind::Updates => self.platform.pending_updates(),
            Kind::Encryption => self.platform.root_encryption(),
            Kind::Identity => unreachable!(),
        }
    }
}

pub fn standalone(platform: &dyn AuditPlatform, clock: &dyn Clock) -> Result<AuditReport, String> {
    collect(platform, clock, true, true)
}

pub fn standalone_with_policy(platform: &dyn AuditPlatform, clock: &dyn Clock, policy: &crate::policy::Policy) -> Result<AuditReport, String> {
    policy.validate()?;
    let mut report = collect(platform, clock, policy.checks.updates.enabled, policy.checks.encryption.enabled)?;
    report.policy_evaluation = Some(crate::policy::evaluate(policy, &report)?);
    Ok(report)
}

fn collect(platform: &dyn AuditPlatform, clock: &dyn Clock, updates_enabled: bool, encryption_enabled: bool) -> Result<AuditReport, String> {
    let os = platform.operating_system();
    let identity = Builtin {
        kind: Kind::Identity,
        platform,
        os: &os,
    };
    let updates = Builtin {
        kind: Kind::Updates,
        platform,
        os: &os,
    };
    let encryption = Builtin {
        kind: Kind::Encryption,
        platform,
        os: &os,
    };
    let report_os = os
        .clone()
        .unwrap_or_else(|_| OperatingSystem::unidentified(std::env::consts::OS));
    let mut checks: Vec<&dyn Check> = vec![&identity];
    if updates_enabled { checks.push(&updates); }
    if encryption_enabled { checks.push(&encryption); }
    audit::run(report_os, &checks, clock)
}
