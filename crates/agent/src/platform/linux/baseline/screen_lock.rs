//! Current-user Plasma 6 Wayland configuration only. No lock/unlock/configure/inhibit calls.
use super::{
    context, error,
    files::{Files, NodeKind},
    host, observed, query,
};
use crate::{
    audit::{Evidence, Outcome, Reason},
    observation::{Observation, Quality, ScreenLock},
    platform::{
        command::{CommandRunner, ProbeError},
        linux::environment::Environment,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
mod kconfig;

#[derive(Clone, Debug)]
pub struct SessionContext {
    pub uid: u32,
    pub home: Option<String>,
    pub config_home: Option<String>,
    pub config_dirs: Option<String>,
    pub kde_version: Option<String>,
}
impl SessionContext {
    pub fn current() -> Self {
        // SAFETY: geteuid takes no arguments and changes no process state.
        Self {
            uid: unsafe { libc::geteuid() },
            home: std::env::var("HOME").ok(),
            config_home: std::env::var("XDG_CONFIG_HOME").ok(),
            config_dirs: std::env::var("XDG_CONFIG_DIRS").ok(),
            kde_version: std::env::var("KDE_SESSION_VERSION").ok(),
        }
    }
}
fn empty(quality: Quality) -> ScreenLock {
    ScreenLock {
        quality,
        session_scope: "CURRENT_USER_SINGLE_PLASMA6_WAYLAND_SESSION_CONFIGURATION".into(),
        capability: None,
        configuration_enabled: None,
        automatic_lock: None,
        idle_timeout_seconds: None,
        grace_seconds: None,
        password_required: None,
        lock_on_resume: None,
        current_screen_saver_active: None,
    }
}
fn result(f: ScreenLock, message: &str) -> Outcome {
    let positive = if f.quality == Quality::Verified {
        Some(
            f.capability == Some(true)
                && f.configuration_enabled == Some(true)
                && f.automatic_lock == Some(true),
        )
    } else {
        None
    };
    observed(Observation::ScreenLock(f.clone()),f.quality,positive,"logind session metadata + owned ScreenSaver GetActive + kreadconfig6 Daemon keys + installed KConfig schema","current user configuration only; no idle enforcement test, inhibitor audit or password-grace completion claim",message)
}
fn invalid(message: &str) -> ProbeError {
    ProbeError::new(Reason::InvalidOutput, message)
}
fn bus(
    runner: &dyn CommandRunner,
    address: &str,
    destination: &str,
    path: &str,
    interface: &str,
    method: &str,
    tail: &[&str],
) -> Result<Value, ProbeError> {
    let mut args = vec![
        address,
        "--auto-start=no",
        "--allow-interactive-authorization=no",
        "--timeout=3",
        "--json=short",
        "call",
        destination,
        path,
        interface,
        method,
    ];
    args.extend_from_slice(tail);
    let text = query(runner, "/usr/bin/busctl", &args)?;
    let json: Value = serde_json::from_str(&text).map_err(|_| invalid("Invalid busctl JSON"))?;
    let signature = match method {
        "NameHasOwner" | "GetActive" => "b",
        "ListSessions" => "a(susso)",
        "GetConnectionUnixUser" => "u",
        "Get" => "v",
        _ => return Err(invalid("Unapproved screen-lock inspection method")),
    };
    if json.get("type").and_then(Value::as_str) != Some(signature) {
        return Err(invalid("Unexpected D-Bus result signature"));
    }
    json.get("data")
        .cloned()
        .ok_or_else(|| invalid("Missing D-Bus result data"))
}
fn scalar(mut v: Value) -> Value {
    for _ in 0..8 {
        if let Some(data) = v.get("data") {
            v = data.clone()
        } else if v.as_array().is_some_and(|a| a.len() == 1) {
            v = v[0].clone()
        } else {
            break;
        }
    }
    v
}
fn owns(runner: &dyn CommandRunner, address: &str, name: &str) -> Result<bool, ProbeError> {
    scalar(bus(
        runner,
        address,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameHasOwner",
        &["s", name],
    )?)
    .as_bool()
    .ok_or_else(|| invalid("Invalid D-Bus owner response"))
}
fn property(runner: &dyn CommandRunner, path: &str, name: &str) -> Result<String, ProbeError> {
    let value = scalar(bus(
        runner,
        "--system",
        "org.freedesktop.login1",
        path,
        "org.freedesktop.DBus.Properties",
        "Get",
        &["ss", "org.freedesktop.login1.Session", name],
    )?);
    if name == "Remote" {
        value
            .as_bool()
            .map(|b| b.to_string())
            .ok_or_else(|| invalid("Invalid boolean logind Remote property"))
    } else {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("Invalid string logind session property"))
    }
}

fn session_rows(mut data: Value) -> Result<Vec<(u32, String)>, ProbeError> {
    // Method response wraps its array in the message argument list. Also accept
    // a directly encoded array; never consume names/seat identifiers into reports.
    if data.as_array().is_some_and(|a| {
        a.len() == 1
            && a[0]
                .as_array()
                .is_some_and(|rows| rows.is_empty() || rows[0].is_array())
    }) {
        data = data[0].clone()
    }
    let rows = data
        .as_array()
        .ok_or_else(|| invalid("Invalid logind session array"))?;
    if rows.len() > 16 {
        return Err(ProbeError::new(
            Reason::OutputLimit,
            "Too many sessions to establish unambiguous user scope",
        ));
    }
    let mut result = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let row = row
            .as_array()
            .filter(|r| r.len() == 5)
            .ok_or_else(|| invalid("Invalid logind session record"))?;
        let uid = row[1]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| invalid("Invalid session UID"))?;
        let path = row[4]
            .as_str()
            .filter(|v| {
                v.starts_with("/org/freedesktop/login1/session/")
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/_".contains(&b))
            })
            .ok_or_else(|| invalid("Invalid session object path"))?;
        if !seen.insert(path) {
            return Err(invalid("Duplicate session object"));
        }
        result.push((uid, path.to_owned()));
    }
    Ok(result)
}
fn boolean(s: &str) -> Result<bool, ProbeError> {
    match s.trim() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(invalid("Invalid screen-lock boolean")),
    }
}
/// Synthetic tests and native reads use the same conversion, including password grace.
pub fn configuration(
    values: &BTreeMap<String, String>,
    active: bool,
) -> Result<ScreenLock, ProbeError> {
    let get = |key| {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| invalid("Incomplete screen-lock settings"))
    };
    let auto = boolean(get("Autolock")?)?;
    let lock = boolean(get("Lock")?)?;
    let password = boolean(get("RequirePassword")?)?;
    let minutes: f64 = get("Timeout")?
        .parse()
        .map_err(|_| invalid("Invalid screen-lock timeout"))?;
    if !minutes.is_finite() || minutes < 0.0 || minutes > f64::from(u32::MAX) / 60.0 {
        return Err(invalid("Out-of-range screen-lock timeout"));
    }
    let grace: u32 = get("LockGrace")?
        .parse()
        .map_err(|_| invalid("Invalid screen-lock grace period"))?;
    let seconds = (minutes * 60.0).ceil() as u32;
    seconds
        .checked_add(grace)
        .ok_or_else(|| invalid("Screen-lock timeout overflow"))?;
    let mut f = empty(Quality::Verified);
    f.capability = Some(true);
    f.configuration_enabled = Some(lock && password);
    f.automatic_lock = Some(auto && seconds > 0);
    f.idle_timeout_seconds = Some(seconds);
    f.grace_seconds = Some(grace);
    f.password_required = Some(password);
    f.lock_on_resume = Some(boolean(get("LockOnResume")?)?);
    f.current_screen_saver_active = Some(active);
    Ok(f)
}
pub fn screen_lock(
    files: &dyn Files,
    runner: &dyn CommandRunner,
    env: &Environment,
    user: &SessionContext,
) -> Outcome {
    if !host(env) {
        return context(
            result(
                empty(Quality::Restricted),
                "Host/user session scope unavailable; no host bus or user configuration accessed",
            ),
            env,
        );
    }
    let mut provenance = None;
    let mut inspect = || -> Result<(ScreenLock, &'static str), ProbeError> {
        if !owns(runner, "--system", "org.freedesktop.login1")? {
            return Ok((
                empty(Quality::Missing),
                "Logind is not already running; no service is activated",
            ));
        }
        let rows = session_rows(bus(
            runner,
            "--system",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "ListSessions",
            &[],
        )?)?;
        let mut graphical = Vec::new();
        for (uid, path) in rows {
            let kind = property(runner, &path, "Type")?;
            if matches!(kind.as_str(), "wayland" | "x11" | "mir" | "web") {
                graphical.push((uid, path, kind))
            } else if kind != "tty" {
                // systemd's per-user service manager can have a separate PAM
                // session, which is not an interactive graphical login.
                if kind == "unspecified"
                    && property(runner, &path, "Class")? == "manager"
                    && property(runner, &path, "Service")? == "systemd-user"
                    && property(runner, &path, "Remote")? == "false"
                {
                    continue;
                }
                return Ok((
                    empty(Quality::Inconclusive),
                    "Unknown session type prevents headless classification",
                ));
            }
        }
        if graphical.is_empty() {
            let mut f = empty(Quality::NotApplicable);
            f.session_scope = "NO_GRAPHICAL_SESSIONS_VERIFIED_BY_LOGIND".into();
            return Ok((f,"No graphical sessions in successful complete logind enumeration; headless screen-lock scope is not applicable"));
        }
        if graphical.len() != 1 {
            return Ok((
                empty(Quality::Inconclusive),
                "Multiple graphical sessions; user security scope is ambiguous",
            ));
        }
        let (uid, session, kind) = &graphical[0];
        if *uid != user.uid {
            return Ok((empty(Quality::Missing),"No uniquely identified current-user graphical session; other users are not inspected"));
        }
        let desktop = property(runner, session, "Desktop")?;
        let class = property(runner, session, "Class")?;
        let remote = property(runner, session, "Remote")?;
        if kind != "wayland"
            || !desktop.split(':').any(|v| v.eq_ignore_ascii_case("KDE"))
            || user.kde_version.as_deref() != Some("6")
            || class != "user"
            || remote != "false"
        {
            return Ok((
                empty(Quality::Unsupported),
                "Only a single local current-user Plasma 6 Wayland session is supported",
            ));
        }
        let address = format!("--address=unix:path=/run/user/{}/bus", user.uid);
        let socket = files.info(&format!("/run/user/{}/bus", user.uid))?;
        if !matches!(socket,Some(n) if n.kind==NodeKind::Socket&&n.owner==user.uid) {
            return Ok((
                empty(Quality::Missing),
                "Owned local user-bus socket unavailable; no remote/inherited bus endpoint used",
            ));
        }
        if !owns(runner, &address, "org.freedesktop.ScreenSaver")? {
            return Ok((
                empty(Quality::Missing),
                "Screen-lock capability is not exposed by an already running session service",
            ));
        }
        let owner = scalar(bus(
            runner,
            &address,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetConnectionUnixUser",
            &["s", "org.freedesktop.ScreenSaver"],
        )?)
        .as_u64()
        .ok_or_else(|| invalid("Invalid screen-lock service UID"))?;
        if owner != u64::from(user.uid) {
            return Ok((
                empty(Quality::Inconclusive),
                "Screen-lock service owner does not match the selected user",
            ));
        }
        let active = scalar(bus(
            runner,
            &address,
            "org.freedesktop.ScreenSaver",
            "/ScreenSaver",
            "org.freedesktop.ScreenSaver",
            "GetActive",
            &[],
        )?)
        .as_bool()
        .ok_or_else(|| invalid("Invalid ScreenSaver active state"))?;
        let mut evidence = json!({"sourceSetEstablished":false,"consistency":"NOT_ESTABLISHED"});
        let result = kconfig::collect(files, runner, user, active, &mut evidence);
        provenance = Some(evidence);
        result
    };
    let mut outcome = match inspect() {
        Ok((f, message)) => result(f, message),
        Err(e) => error(
            result(
                empty(Quality::Inconclusive),
                "User session/configuration unavailable",
            ),
            e,
        ),
    };
    if let Some(provenance) = provenance {
        outcome = outcome.with_evidence(Evidence::new(
            "SEC-007 KConfig candidate-source provenance",
            "standard Linux Qt6/KConfig6 resolution; bounded before/after comparison, not atomic or runtime attestation",
            &[("configurationProvenance", provenance)],
        ));
    }
    context(outcome, env)
}
