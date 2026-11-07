//! Opt-in shipped check pack. No arbitrary scripts, remote execution or transport.
use crate::{
    audit::{AuditReport, Clock, Outcome, Status},
    check_port::{Availability, CheckEvidence, CheckExecutor, ExecutionState},
    checks::builtin,
    cli::{Error, Output},
    platform::AuditPlatform,
    policy::{self, Policy},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::Read,
    path::Path,
};

pub const IDS: &[&str] = &[
    "SEC-001", "SEC-003", "SEC-004", "SEC-006", "SEC-007", "SEC-008", "SEC-009", "SEC-010",
    "SEC-011", "SEC-012", "SEC-013", "SEC-014", "SEC-015", "SEC-016", "SEC-017",
];
const INDICATOR_IDS: &[&str] = &["SEC-003", "SEC-004", "SEC-011"];
const DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "SEC-001",
        "Inspects cached Arch pacman or Fedora DNF5 update availability; does not establish vulnerability status or upstream freshness.",
    ),
    (
        "SEC-003",
        "Observes ClamAV service state and candidate prevention/signature indicators; does not prove scan coverage or signature freshness.",
    ),
    (
        "SEC-004",
        "Observes candidate DNS filtering configuration such as hosts, dnsmasq and resolver setup; does not prove traffic is filtered.",
    ),
    (
        "SEC-006",
        "Traces root filesystem backing devices and checks whether the complete supported device chain uses active LUKS encryption.",
    ),
    (
        "SEC-007",
        "Observes automatic screen-lock settings for a single current-user Plasma 6 Wayland session.",
    ),
    (
        "SEC-008",
        "Observes effective password-aging limits for ordinary local interactive accounts; account-creation defaults are separate.",
    ),
    (
        "SEC-009",
        "Observes configured account password-expiry warning periods; directory and identity-provider accounts are outside scope.",
    ),
    (
        "SEC-010",
        "Observes configured password-quality requirements and evidence about their application; configuration alone does not prove enforcement.",
    ),
    (
        "SEC-011",
        "Observes the installed Cato VPN client configuration and reported status; this does not prove tunnel reachability.",
    ),
    (
        "SEC-012",
        "Observes cached kernel TPM version, device identity and read permissions without issuing TPM commands.",
    ),
    (
        "SEC-013",
        "Observes UEFI Secure Boot and SetupMode variables; it does not verify the complete boot chain or module trust.",
    ),
    (
        "SEC-014",
        "Separates firewall manager state from available evidence of IPv4 and IPv6 Netfilter INPUT filtering.",
    ),
    (
        "SEC-015",
        "Inspects encryption for the current user's home mount and its backing storage.",
    ),
    (
        "SEC-016",
        "Inspects encryption coverage only for sensitive paths explicitly authorized by the selected policy.",
    ),
    (
        "SEC-017",
        "Inspects all active swap devices and files for supported encryption evidence.",
    ),
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Assignment {
    pub enabled: bool,
    pub mandatory: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Supplemental {
    #[serde(rename = "SEC-003")]
    pub antivirus: Assignment,
    #[serde(rename = "SEC-004")]
    pub filtering: Assignment,
    #[serde(rename = "SEC-011")]
    pub vpn: Assignment,
}
impl Supplemental {
    fn get(&self, id: &str) -> &Assignment {
        match id {
            "SEC-003" => &self.antivirus,
            "SEC-004" => &self.filtering,
            _ => &self.vpn,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackPolicy {
    pub schema_version: String,
    pub native_policy: Policy,
    pub supplemental: Supplemental,
}
impl PackPolicy {
    pub fn from_json(text: &str) -> Result<Self, String> {
        if text.len() > 65536 {
            return Err("Pack policy exceeds 64 KiB".into());
        }
        let mut p: Self = serde_json::from_str(text).map_err(|_| "Invalid pack policy JSON")?;
        if p.schema_version != "baradwatchu.workstation-policy.v1" {
            return Err("Unsupported pack policy schema".into());
        }
        p.native_policy = Policy::from_json(
            &serde_json::to_string(&p.native_policy).map_err(|_| "Invalid native policy")?,
        )?;
        Ok(p)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalSelection {
    pub schema_version: String,
    pub disabled: Vec<String>,
}
impl Default for LocalSelection {
    fn default() -> Self {
        Self {
            schema_version: "baradwatchu.workstation-local.v1".into(),
            disabled: vec![],
        }
    }
}
impl LocalSelection {
    pub fn from_json(text: &str) -> Result<Self, String> {
        if text.len() > 65536 {
            return Err("Local selection exceeds 64 KiB".into());
        }
        let p: Self = serde_json::from_str(text).map_err(|_| "Invalid local selection JSON")?;
        p.validate()?;
        Ok(p)
    }
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != "baradwatchu.workstation-local.v1"
            || self.disabled.iter().any(|s| !IDS.contains(&s.as_str()))
            || self.disabled.iter().collect::<BTreeSet<_>>().len() != self.disabled.len()
        {
            return Err("Invalid local schema, unknown or duplicate check ID".into());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Execution {
    pub id: String,
    pub version: String,
    pub implementation: &'static str,
    pub desired_enabled: bool,
    pub mandatory: bool,
    pub locally_disabled: bool,
    pub execution: &'static str,
    pub required_check_interrupted: bool,
    pub evaluation: Option<Status>,
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_state: Option<ExecutionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_availability: Option<Availability>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: &'static str,
    pub policy_authority: &'static str,
    pub remote_delivery: &'static str,
    pub completed_at_unix_ms: u64,
    pub overall: Status,
    pub native_report: AuditReport,
    pub checks: Vec<Execution>,
}
impl Report {
    pub fn exit_code(&self) -> u8 {
        match self.overall {
            Status::Pass => 0,
            Status::Error => 1,
            Status::Fail => 3,
            _ => 4,
        }
    }
}
fn rank(s: Status) -> u8 {
    match s {
        Status::Error => 4,
        Status::Fail => 3,
        Status::Warn | Status::NotApplicable => 2,
        Status::Pass => 1,
    }
}

pub fn audit(
    platform: &dyn AuditPlatform,
    clock: &dyn Clock,
    desired: &PackPolicy,
    local: &LocalSelection,
    collect: impl FnMut(&str) -> Outcome,
) -> Result<Report, String> {
    let targets = desired
        .native_policy
        .checks
        .sensitive_encryption
        .as_ref()
        .map(|p| p.targets.as_slice())
        .unwrap_or(&[]);
    let executor = crate::adapters::LegacyExecutor {
        native: crate::adapters::LocalExecutor::new(platform, targets),
        collect: RefCell::new(collect),
    };
    audit_with_executor(platform, clock, desired, local, &executor)
}

struct Recorded<'a> {
    inner: &'a dyn CheckExecutor,
    results: RefCell<BTreeMap<String, CheckEvidence>>,
}
impl CheckExecutor for Recorded<'_> {
    fn execute(&self, id: &str) -> CheckEvidence {
        let result = self.inner.execute(id);
        self.results.borrow_mut().insert(id.into(), result.clone());
        result
    }
    fn implementation(&self, id: &str) -> &'static str {
        self.inner.implementation(id)
    }
}
pub fn audit_with_executor(
    platform: &dyn AuditPlatform,
    clock: &dyn Clock,
    desired: &PackPolicy,
    local: &LocalSelection,
    executor: &dyn CheckExecutor,
) -> Result<Report, String> {
    let recorded = Recorded {
        inner: executor,
        results: RefCell::new(BTreeMap::new()),
    };
    local.validate()?;
    let desired =
        PackPolicy::from_json(&serde_json::to_string(desired).map_err(|_| "Invalid policy")?)?;
    let original =
        serde_json::to_value(&desired.native_policy).map_err(|_| "Invalid native policy")?;
    let mut selected = original.clone();
    for id in &local.disabled {
        if let Some(value) = selected["checks"].get_mut(id) {
            value["enabled"] = json!(false);
        }
    }
    let selected = Policy::from_json(&selected.to_string())?;
    let bridge = crate::adapters::PortPlatform {
        context: platform,
        executor: &recorded,
        aging_id: if selected.enabled("SEC-008") {
            "SEC-008"
        } else {
            "SEC-009"
        },
    };
    let mut native = builtin::standalone_with_policy(&bridge, clock, &selected)?;
    // Assess the ORIGINAL policy against collected evidence, never the reduced selection.
    native.policy_evaluation = Some(policy::evaluate(&desired.native_policy, &native)?);
    let mut overall = native
        .policy_evaluation
        .as_ref()
        .ok_or("Missing evaluation")?
        .overall;
    let mut checks = Vec::new();
    for id in IDS {
        let indicator = INDICATOR_IDS.contains(id);
        let (enabled, mandatory) = if indicator {
            let p = desired.supplemental.get(id);
            (p.enabled, p.mandatory)
        } else {
            let p = &original["checks"][id];
            (
                p["enabled"].as_bool().unwrap_or(false),
                p["mandatory"].as_bool().unwrap_or(false),
            )
        };
        let disabled = local.disabled.iter().any(|s| s == id);
        let interrupted = enabled && mandatory && disabled;
        let outcome = if enabled && !disabled {
            if indicator {
                Some(recorded.execute(id).outcome)
            } else {
                native
                    .results
                    .iter()
                    .find(|r| r.check.id == *id)
                    .map(|r| r.outcome.clone())
            }
        } else {
            None
        };
        let evaluation = if interrupted {
            Some(Status::Fail)
        } else if !enabled || disabled {
            None
        } else if indicator {
            Some(Status::Warn)
        }
        // Indicators cannot certify protection.
        else {
            native
                .policy_evaluation
                .as_ref()
                .and_then(|p| p.checks.iter().find(|c| c.check_id == *id))
                .and_then(|c| c.status)
        };
        if enabled && mandatory {
            let candidate = evaluation.unwrap_or(Status::Warn);
            if rank(candidate) > rank(overall) {
                overall = candidate;
            }
        }
        let execution_evidence = if enabled && !disabled {
            let results = recorded.results.borrow();
            results
                .get(*id)
                .or_else(|| {
                    if *id == "SEC-009" {
                        results.get("SEC-008")
                    } else {
                        None
                    }
                })
                .cloned()
        } else {
            None
        };
        checks.push(Execution {
            id: (*id).into(),
            version: if indicator {
                "1.0.0".into()
            } else {
                native
                    .results
                    .iter()
                    .find(|r| r.check.id == *id)
                    .map(|r| r.check.version.clone())
                    .unwrap_or_else(|| "NOT_EXECUTED".into())
            },
            implementation: executor.implementation(id),
            desired_enabled: enabled,
            mandatory,
            locally_disabled: disabled,
            execution: if disabled {
                "DISABLED_LOCAL"
            } else if !enabled {
                "DISABLED_POLICY"
            } else {
                "ATTEMPTED"
            },
            required_check_interrupted: interrupted,
            evaluation,
            outcome,
            execution_state: execution_evidence.as_ref().map(|e| e.execution),
            evidence_availability: execution_evidence.as_ref().map(|e| e.availability),
        });
    }
    Ok(Report {
        schema_version: "baradwatchu.workstation-report.v1",
        policy_authority: "LOCAL_FILE_UNAUTHENTICATED",
        remote_delivery: "NOT_IMPLEMENTED",
        completed_at_unix_ms: clock.now_unix_ms()?,
        overall,
        native_report: native,
        checks,
    })
}

pub use crate::adapters::legacy::{collect_script, parse_facts};
fn read_config(path: &Path) -> Result<String, String> {
    if !std::fs::metadata(path)
        .map_err(|_| "Cannot inspect configuration")?
        .is_file()
    {
        return Err("Configuration must be a regular file".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "Cannot read configuration")?;
    if !file
        .metadata()
        .map_err(|_| "Cannot inspect configuration")?
        .is_file()
    {
        return Err("Configuration must be a regular file".into());
    }
    let mut text = String::new();
    file.take(65537)
        .read_to_string(&mut text)
        .map_err(|_| "Cannot read configuration")?;
    if text.len() > 65536 {
        return Err("Configuration exceeds 64 KiB".into());
    }
    Ok(text)
}
pub fn cli(
    args: &[OsString],
    platform: &dyn AuditPlatform,
    clock: &dyn Clock,
) -> Result<Output, Error> {
    fn error(message: impl Into<String>) -> Error {
        Error {
            message: message.into(),
            code: 2,
        }
    }
    fn output(value: impl Serialize, code: u8) -> Result<Output, Error> {
        Ok(Output {
            text: serde_json::to_string_pretty(&value)
                .map_err(|_| error("Cannot serialize report"))?
                + "\n",
            code,
        })
    }
    match args {
        [cmd] if cmd == "list" => {
            let descriptions: BTreeMap<_, _> = DESCRIPTIONS.iter().copied().collect();
            let registrations = crate::adapters::descriptors()
                .into_iter()
                .map(|mut registration| {
                    if let Some(id) = registration.get("id").and_then(serde_json::Value::as_str) {
                        if let Some(description) = descriptions.get(id) {
                            registration["description"] = json!(description);
                        }
                    }
                    registration
                })
                .collect::<Vec<_>>();
            return output(
                json!({
                    "schemaVersion": "baradwatchu.workstation-registry.v1",
                    "registrations": registrations
                }),
                0,
            );
        }
        [cmd, id] if cmd == "check" => {
            let id = id
                .to_str()
                .filter(|id| IDS.contains(id))
                .ok_or_else(|| error("Unknown shipped check ID"))?;
            let evidence = crate::adapters::LocalExecutor::new(platform, &[]).execute(id);
            let outcome = evidence.outcome;
            return output(
                json!({"id":id,"compliance":"NOT_EVALUATED","outcome":outcome,"executionState":evidence.execution,"evidenceAvailability":evidence.availability}),
                4,
            );
        }
        [cmd, path] if cmd == "validate" => {
            PackPolicy::from_json(&read_config(Path::new(path)).map_err(error)?).map_err(error)?;
            return output(json!({"valid":true}), 0);
        }
        _ => {}
    }
    if args.first().map_or(true, |cmd| cmd != "audit") {
        return Err(error("Usage: workstation list | check ID | validate FILE | audit --policy FILE [--local-config FILE]"));
    }
    let mut path = None;
    let mut local_path = None;
    for pair in args[1..].chunks(2) {
        if pair.len() != 2 || pair[1].is_empty() {
            return Err(error("Missing option value"));
        }
        if pair[0] == "--policy" && path.is_none() {
            path = Some(Path::new(&pair[1]));
        } else if pair[0] == "--local-config" && local_path.is_none() {
            local_path = Some(Path::new(&pair[1]));
        } else {
            return Err(error("Unknown or repeated workstation option"));
        }
    }
    let desired = PackPolicy::from_json(
        &read_config(path.ok_or_else(|| error("Explicit workstation policy required"))?)
            .map_err(error)?,
    )
    .map_err(error)?;
    let local = match local_path {
        Some(path) => {
            LocalSelection::from_json(&read_config(path).map_err(error)?).map_err(error)?
        }
        None => LocalSelection::default(),
    };
    let targets = desired
        .native_policy
        .checks
        .sensitive_encryption
        .as_ref()
        .map(|p| p.targets.as_slice())
        .unwrap_or(&[]);
    let executor = crate::adapters::LocalExecutor::new(platform, targets);
    let report =
        audit_with_executor(platform, clock, &desired, &local, &executor).map_err(error)?;
    let code = report.exit_code();
    output(report, code)
}
