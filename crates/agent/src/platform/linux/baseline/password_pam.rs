//! Conservative configured password-change proof, not a password-change test.
//! Only a requisite quality gate before a use_authtok local writer proves that
//! rejection prevents a write. `required` alone can fail after pam_unix commits.
use super::{
    context,
    credential_sources::{name, unavailable, Snapshot},
    files::Files,
    host, observed,
    password_quality::QualitySettings,
};
use crate::{
    audit::Outcome,
    observation::{Observation, PasswordComplexity, PasswordRequirements, PasswordStack, Quality},
    platform::{command::ProbeError, linux::environment::Environment},
};
use std::collections::{BTreeMap, BTreeSet};

const SCOPE: &str = "CONFIGURED_PAM_PASSWORD_STACKS_LOCAL_ACCOUNTS; no existing-password, module-binary, runtime or non-PAM administrator attestation";
fn empty() -> PasswordComplexity {
    PasswordComplexity {
        quality: Quality::Inconclusive,
        scope: SCOPE.into(),
        stacks: vec![],
    }
}
pub fn observe(files: &dyn Files, env: &Environment) -> Outcome {
    let facts = if !host(env) {
        PasswordComplexity {
            quality: Quality::Restricted,
            ..empty()
        }
    } else {
        collect(files).unwrap_or_else(|_| empty())
    };
    context(observed(Observation::PasswordComplexity(facts.clone()), facts.quality, None,
        "PAM password configuration graph and ordered pwquality configuration; before/after consistency checks",
        SCOPE, "Configured enforcement analysis; unsupported flow or missing facts cannot certify compliance"), env)
}
#[derive(Clone, Debug)]
enum Step {
    Module {
        control: String,
        module: String,
        args: Vec<String>,
    },
    Substack(Vec<Step>),
}

fn lines(text: &str) -> Result<Vec<String>, ProbeError> {
    let mut result = vec![];
    let mut current = String::new();
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if let Some(l) = l.strip_suffix('\\') {
            current.push_str(l);
            current.push(' ');
        } else {
            current.push_str(l);
            if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
        }
        if current.len() > 8192 {
            return Err(unavailable());
        }
    }
    if !current.is_empty() {
        return Err(unavailable());
    }
    Ok(result)
}
fn expand(
    service: &str,
    sources: &BTreeMap<String, String>,
    visiting: &mut BTreeSet<String>,
    count: &mut usize,
) -> Result<Vec<Step>, ProbeError> {
    if !name(service) || visiting.len() >= 16 || !visiting.insert(service.into()) {
        return Err(unavailable());
    }
    let text = sources.get(service).ok_or_else(unavailable)?;
    let mut steps = vec![];
    for line in lines(text)? {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        let (control, target, args) = if words[0] == "@include" && words.len() == 2 {
            ("include", words[1], &words[2..])
        } else {
            if !words[0]
                .trim_start_matches('-')
                .eq_ignore_ascii_case("password")
            {
                continue;
            }
            if words.len() < 3 {
                return Err(unavailable());
            }
            (words[1], words[2], &words[3..])
        };
        *count += 1;
        if *count > 256 {
            return Err(unavailable());
        }
        if control.eq_ignore_ascii_case("include") || control.eq_ignore_ascii_case("substack") {
            if !args.is_empty() {
                return Err(unavailable());
            }
            let inner = expand(target, sources, visiting, count)?;
            if control.eq_ignore_ascii_case("include") {
                steps.extend(inner);
            } else {
                steps.push(Step::Substack(inner));
            }
        } else {
            steps.push(Step::Module {
                control: control.to_ascii_lowercase(),
                module: target.into(),
                args: args.iter().map(|s| (*s).into()).collect(),
            });
        }
    }
    visiting.remove(service);
    Ok(steps)
}
fn requirements(s: &QualitySettings) -> PasswordRequirements {
    PasswordRequirements {
        minimum_length: s.min_length,
        minimum_classes: s.min_classes,
        credits: [
            s.upper_credit,
            s.lower_credit,
            s.digit_credit,
            s.other_credit,
        ],
        enforcing: s.enforcing,
        enforce_for_root: s.enforce_for_root,
    }
}
fn analyze(
    steps: &[Step],
    base: &QualitySettings,
) -> (bool, Option<PasswordRequirements>, &'static str) {
    // A wrapper containing only a substack preserves its result and has no later
    // password writer. More general substack early-return semantics stay unknown.
    if let [Step::Substack(inner)] = steps {
        return analyze(inner, base);
    }
    let mut gate = None;
    let mut writer = false;
    for step in steps {
        let Step::Module {
            control,
            module,
            args,
        } = step
        else {
            return (false, gate, "SUBSTACK_CONTINUATION_UNPROVEN");
        };
        // Extended controls may jump, reset failures or terminate successfully.
        if !matches!(
            control.as_str(),
            "required" | "requisite" | "sufficient" | "optional"
        ) {
            return (false, gate, "PAM_CONTROL_FLOW_UNSUPPORTED");
        }
        match module.as_str() {
            "pam_pwquality.so" => {
                if gate.is_some() || writer {
                    return (false, gate, "QUALITY_GATE_ORDER_UNPROVEN");
                }
                let mut settings = base.clone();
                if settings
                    .apply_arguments(args.iter().map(String::as_str))
                    .is_err()
                {
                    return (false, None, "PWQUALITY_ARGUMENTS_UNSUPPORTED");
                }
                gate = Some(requirements(&settings));
                if control != "requisite" {
                    return (false, gate, "QUALITY_REJECTION_MAY_REACH_WRITER");
                }
                if settings.enforcing != Some(true) || settings.enforce_for_root != Some(true) {
                    return (false, gate, "QUALITY_ENFORCEMENT_OR_ROOT_EXCEPTION_UNKNOWN");
                }
            }
            "pam_unix.so" => {
                if gate.is_none()
                    || writer
                    || !matches!(control.as_str(), "required" | "requisite" | "sufficient")
                    || !args.iter().any(|s| s == "use_authtok")
                {
                    return (false, gate, "LOCAL_WRITER_WITHOUT_PROVEN_QUALITY_GATE");
                }
                if args.iter().any(|s| {
                    !matches!(
                        s.as_str(),
                        "use_authtok"
                            | "try_first_pass"
                            | "shadow"
                            | "yescrypt"
                            | "sha512"
                            | "sha256"
                            | "md5"
                            | "bigcrypt"
                            | "obscure"
                            | "nullok"
                            | "nodelay"
                    )
                }) {
                    return (false, gate, "LOCAL_WRITER_OPTIONS_UNSUPPORTED");
                }
                writer = true;
            }
            "pam_deny.so"
                if args.is_empty() && matches!(control.as_str(), "required" | "requisite") =>
            {
                if !writer {
                    return (false, gate, "PASSWORD_CHANGE_DENIED_NOT_QUALITY_PROOF");
                }
            }
            "pam_permit.so" if args.is_empty() && control != "sufficient" => {}
            // Unknown modules may replace PAM_AUTHTOK, write a password or bypass
            // later modules; do not infer behavior from a module filename alone.
            _ => return (false, gate, "PAM_MODULE_OR_BYPASS_UNPROVEN"),
        }
    }
    if writer {
        (
            true,
            gate,
            "REQUISITE_QUALITY_BEFORE_LOCAL_USE_AUTHTOK_WRITER",
        )
    } else {
        (false, gate, "NO_PROVEN_LOCAL_PASSWORD_WRITER")
    }
}
fn denies_changes(steps: &[Step]) -> bool {
    if let [Step::Substack(inner)] = steps {
        return denies_changes(inner);
    }
    let mut deny = false;
    for step in steps {
        match step {
            Step::Module {
                control,
                module,
                args,
            } if args.is_empty()
                && module == "pam_deny.so"
                && matches!(control.as_str(), "required" | "requisite") =>
            {
                deny = true
            }
            Step::Module {
                control,
                module,
                args,
            } if args.is_empty()
                && module == "pam_warn.so"
                && matches!(control.as_str(), "required" | "optional") => {}
            _ => return false,
        }
    }
    deny
}
fn collect(files: &dyn Files) -> Result<PasswordComplexity, ProbeError> {
    let mut snapshot = Snapshot::new(files);
    let mut services = BTreeSet::new();
    for dir in ["/etc/pam.d", "/usr/lib/pam.d"] {
        services.extend(snapshot.entries(dir)?);
    }
    if !services.contains("passwd") {
        return Err(unavailable());
    }
    let mut sources = BTreeMap::new();
    for service in &services {
        let local = snapshot.read(&format!("/etc/pam.d/{service}"))?;
        let vendor = snapshot.read(&format!("/usr/lib/pam.d/{service}"))?;
        if let Some(data) = local.or(vendor) {
            sources.insert(service.clone(), data);
        }
    }
    // New vendor pwquality layouts are version dependent. Do not guess their
    // merge semantics on an installed older library.
    if snapshot.read("/usr/lib/security/pwquality.conf")?.is_some()
        || !snapshot
            .entries("/usr/lib/security/pwquality.conf.d")?
            .is_empty()
    {
        return Err(unavailable());
    }
    let mut settings = QualitySettings::default();
    for file in snapshot.entries("/etc/security/pwquality.conf.d")? {
        if file.ends_with(".conf") {
            settings
                .apply_file(&snapshot.required(&format!("/etc/security/pwquality.conf.d/{file}"))?)
                .map_err(|_| unavailable())?;
        }
    }
    if let Some(main) = snapshot.read("/etc/security/pwquality.conf")? {
        settings.apply_file(&main).map_err(|_| unavailable())?;
    }
    let mut stacks = vec![];
    for service in sources.keys() {
        let result = expand(service, &sources, &mut BTreeSet::new(), &mut 0);
        // Inspect every configured password stack, including common fragments:
        // this deliberately prefers a warning to missing an alternate entrypoint.
        if result.as_ref().is_ok_and(|s| s.is_empty()) && service != "passwd" {
            continue;
        }
        let denied = result.as_ref().is_ok_and(|s| denies_changes(s));
        let (proven, requirements, reason) = match result {
            Ok(s) => analyze(&s, &settings),
            Err(_) => (false, None, "PAM_INCLUDE_MISSING_CYCLIC_OR_UNSUPPORTED"),
        };
        stacks.push(PasswordStack {
            id: format!("stack-{}", stacks.len() + 1),
            quality: if proven || denied {
                Quality::Verified
            } else {
                Quality::Inconclusive
            },
            enforcement_proven: proven,
            password_changes_denied: denied,
            requirements,
            reason: if denied {
                "STACK_DENIES_PASSWORD_CHANGES"
            } else {
                reason
            }
            .into(),
        });
    }
    snapshot.consistent()?;
    Ok(PasswordComplexity {
        quality: Quality::Verified,
        scope: SCOPE.into(),
        stacks,
    })
}
