//! Pure tray logic (no GUI): agent snapshot model, icon state, notification policy, texts.
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Warning,
    Critical,
    Action,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: u64,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub repeated: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    pub enabled: bool,
    pub informative: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            enabled: true,
            informative: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Consent {
    pub request_id: String,
    pub prompt: String,
    pub remaining_seconds: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditDigest {
    pub completed_at_unix_ms: u64,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub error: usize,
    #[serde(default)]
    pub integrity_issues: Vec<String>,
    #[serde(default)]
    pub execution_errors: Vec<String>,
    #[serde(default)]
    pub custom_checks: usize,
    #[serde(default)]
    pub custom_not_pass: usize,
}

/// Output of `baradwatchu-agent events --json`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub agent_version: String,
    pub latest_event_id: u64,
    pub events: Vec<Event>,
    pub preferences: Preferences,
    pub pending_consents: Vec<Consent>,
    pub last_audit: Option<AuditDigest>,
    #[serde(default)]
    pub last_audit_error: Option<String>,
}

pub fn parse_snapshot(text: &str) -> Result<Snapshot, String> {
    serde_json::from_str(text).map_err(|_| "risposta dell'agente non valida".to_owned())
}

/// What the icon shows, most urgent first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Unreachable,
    Attention,
    Critical,
    Anomalies,
    NoAudit,
    Ok,
}

pub fn health(snapshot: Option<&Snapshot>) -> Health {
    let Some(snapshot) = snapshot else {
        return Health::Unreachable;
    };
    if !snapshot.pending_consents.is_empty() {
        return Health::Attention;
    }
    match &snapshot.last_audit {
        None => Health::NoAudit,
        Some(audit) if !audit.integrity_issues.is_empty() || audit.error > 0 => Health::Critical,
        Some(audit) if audit.fail > 0 || audit.warn > 0 => Health::Anomalies,
        Some(_) => Health::Ok,
    }
}

#[cfg(test)]
pub fn health_label(health: Health) -> &'static str {
    match health {
        Health::Unreachable => "agente non raggiungibile",
        Health::Attention => "richiesta in attesa di decisione",
        Health::Critical => "errori o problemi di integrità",
        Health::Anomalies => "audit con anomalie",
        Health::NoAudit => "operativo, nessun audit eseguito",
        Health::Ok => "operativo",
    }
}

pub fn health_label_in(health: Health, language: baradwatchu_messages::Language) -> &'static str {
    let key = match health {
        Health::Unreachable => "tray.health_unreachable",
        Health::Attention => "tray.health_attention",
        Health::Critical => "tray.health_critical",
        Health::Anomalies => "tray.health_anomalies",
        Health::NoAudit => "tray.health_no_audit",
        Health::Ok => "tray.health_ok",
    };
    baradwatchu_messages::message(key, language)
}

#[cfg(test)]
pub fn age(now_ms: u64, then_ms: u64) -> String {
    age_in(now_ms, then_ms, baradwatchu_messages::Language::Italian)
}

fn age_in(now_ms: u64, then_ms: u64, language: baradwatchu_messages::Language) -> String {
    let seconds = now_ms.saturating_sub(then_ms) / 1000;
    match seconds {
        0..=59 => baradwatchu_messages::message("tray.age.seconds", language).into(),
        60..=3599 => baradwatchu_messages::message("tray.age.minutes", language)
            .replace("{count}", &(seconds / 60).to_string()),
        3600..=86_399 => baradwatchu_messages::message("tray.age.hours", language)
            .replace("{count}", &(seconds / 3600).to_string()),
        _ => baradwatchu_messages::message("tray.age.days", language)
            .replace("{count}", &(seconds / 86_400).to_string()),
    }
}

fn counts(audit: &AuditDigest) -> String {
    format!(
        "PASS {} · FAIL {} · WARN {} · ERROR {}",
        audit.pass, audit.fail, audit.warn, audit.error
    )
}

/// Multi-line summary for the tooltip and the "last result" window. Integrity and custom
/// checks are reported separately and PASS is never presented as a certification.
#[cfg(test)]
pub fn summary(snapshot: Option<&Snapshot>, comm_error: Option<&str>, now_ms: u64) -> String {
    let health = health(snapshot);
    let mut lines = vec![format!("BaradWatchU — {}", health_label(health))];
    let Some(snapshot) = snapshot else {
        lines.push(comm_error.unwrap_or("Agente non raggiungibile").to_owned());
        lines.push("Nuovo tentativo automatico tra pochi secondi.".into());
        return lines.join("\n");
    };
    match &snapshot.last_audit {
        Some(audit) => {
            lines.push(format!(
                "Ultimo audit: {} — {}",
                age(now_ms, audit.completed_at_unix_ms),
                counts(audit)
            ));
            lines.push(if audit.integrity_issues.is_empty() {
                "Integrità dei tool: nessun blocco".into()
            } else {
                format!(
                    "Integrità: {} controlli non eseguiti ({})",
                    audit.integrity_issues.len(),
                    audit.integrity_issues.join(", ")
                )
            });
            if !audit.execution_errors.is_empty() {
                lines.push(format!(
                    "Controlli in errore: {}",
                    audit.execution_errors.join(", ")
                ));
            }
            if audit.custom_checks > 0 {
                lines.push(format!(
                    "Controlli personalizzati: {} ({} non PASS; esito dichiarato dal tool)",
                    audit.custom_checks, audit.custom_not_pass
                ));
            }
            lines.push("Esito dei controlli locali: non è una certificazione di sicurezza.".into());
        }
        None => lines.push(match &snapshot.last_audit_error {
            Some(error) => format!("Ultimo audit illeggibile: {error}"),
            None => "Nessun audit eseguito.".into(),
        }),
    }
    if !snapshot.pending_consents.is_empty() {
        lines.push(format!(
            "Richieste di consenso in sospeso: {}",
            snapshot.pending_consents.len()
        ));
    }
    lines.join("\n")
}

pub fn summary_in(
    snapshot: Option<&Snapshot>,
    comm_error: Option<&str>,
    now_ms: u64,
    language: baradwatchu_messages::Language,
) -> String {
    let health = health(snapshot);
    let mut lines = vec![format!(
        "BaradWatchU — {}",
        health_label_in(health, language)
    )];
    let Some(snapshot) = snapshot else {
        lines.push(
            comm_error
                .unwrap_or(baradwatchu_messages::message(
                    "tray.health_unreachable",
                    language,
                ))
                .to_owned(),
        );
        lines.push(baradwatchu_messages::message("tray.retry", language).into());
        return lines.join("\n");
    };
    if let Some(audit) = &snapshot.last_audit {
        lines.push(
            baradwatchu_messages::message("tray.summary.last", language)
                .replace(
                    "{age}",
                    &age_in(now_ms, audit.completed_at_unix_ms, language),
                )
                .replace("{counts}", &counts(audit)),
        );
        lines.push(if audit.integrity_issues.is_empty() {
            baradwatchu_messages::message("tray.summary.integrity_clear", language).into()
        } else {
            baradwatchu_messages::message("tray.summary.integrity_blocked", language)
                .replace("{count}", &audit.integrity_issues.len().to_string())
                .replace("{ids}", &audit.integrity_issues.join(", "))
        });
        if !audit.execution_errors.is_empty() {
            lines.push(
                baradwatchu_messages::message("tray.summary.errors", language)
                    .replace("{ids}", &audit.execution_errors.join(", ")),
            );
        }
        if audit.custom_checks > 0 {
            lines.push(
                baradwatchu_messages::message("tray.summary.custom", language)
                    .replace("{total}", &audit.custom_checks.to_string())
                    .replace("{not_pass}", &audit.custom_not_pass.to_string()),
            );
        }
        lines.push(baradwatchu_messages::message("tray.summary.disclaimer", language).into());
    } else if let Some(error) = &snapshot.last_audit_error {
        lines.push(
            baradwatchu_messages::message("tray.summary.unreadable", language)
                .replace("{error}", error),
        );
    } else {
        lines.push(
            baradwatchu_messages::message(
                if language.effective() == baradwatchu_messages::Language::Italian {
                    "tray.no_audit"
                } else {
                    "tray.no_audit"
                },
                language,
            )
            .to_owned(),
        );
    }
    lines.push(
        baradwatchu_messages::message("tray.summary.pending", language)
            .replace("{count}", &snapshot.pending_consents.len().to_string()),
    );
    lines.join("\n")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Urgency {
    Low,
    Normal,
    Critical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Note {
    pub title: String,
    pub body: String,
    pub urgency: Urgency,
}

/// Agent events → native notifications, with deduplication and burst control.
pub fn wants(event: &Event, preferences: Preferences) -> bool {
    match event.severity {
        // Consent requests always surface (they also open the consent window).
        Severity::Action => true,
        _ if !preferences.enabled => false,
        Severity::Info => preferences.informative,
        _ if event.repeated => preferences.informative,
        Severity::Warning | Severity::Critical => true,
    }
}

const MAX_NOTES_PER_POLL: usize = 3;
/// Consecutive failed polls before "agent unreachable" is notified (avoids flapping).
const FAILURES_BEFORE_ALERT: u32 = 2;

#[derive(Debug, Default)]
pub struct Notifier {
    cursor: Option<u64>,
    failures: u32,
    lost_notified: bool,
    preferences: Preferences,
}

impl Notifier {
    pub fn cursor(&self) -> Option<u64> {
        self.cursor
    }

    pub fn on_snapshot(&mut self, snapshot: &Snapshot) -> Vec<Note> {
        self.preferences = snapshot.preferences;
        let mut notes = vec![];
        if self.lost_notified && self.preferences.enabled && self.preferences.informative {
            notes.push(Note {
                title: "BaradWatchU: agente di nuovo raggiungibile".into(),
                body: "La comunicazione con l'agente locale è ripristinata.".into(),
                urgency: Urgency::Low,
            });
        }
        self.failures = 0;
        self.lost_notified = false;
        let Some(cursor) = self.cursor else {
            // First contact: start after the existing log, never replay a backlog.
            self.cursor = Some(snapshot.latest_event_id);
            return notes;
        };
        let mut fresh = snapshot
            .events
            .iter()
            .filter(|event| event.id > cursor && wants(event, self.preferences))
            .collect::<Vec<_>>();
        self.cursor = Some(cursor.max(snapshot.latest_event_id));
        // Most urgent first; keep a few and summarize the rest in one notification.
        fresh.sort_by_key(|event| match event.severity {
            Severity::Action => 0,
            Severity::Critical => 1,
            Severity::Warning => 2,
            Severity::Info => 3,
        });
        let extra = fresh.len().saturating_sub(MAX_NOTES_PER_POLL);
        for event in fresh.iter().take(MAX_NOTES_PER_POLL) {
            notes.push(Note {
                title: event.title.clone(),
                body: event.body.clone(),
                urgency: match event.severity {
                    Severity::Info => Urgency::Low,
                    Severity::Warning => Urgency::Normal,
                    Severity::Critical | Severity::Action => Urgency::Critical,
                },
            });
        }
        if extra > 0 {
            let language = baradwatchu_messages::configured_language();
            notes.push(Note {
                title: baradwatchu_messages::message("tray.notice.more_title", language).into(),
                body: baradwatchu_messages::message("tray.notice.more_body", language)
                    .replace("{count}", &extra.to_string()),
                urgency: Urgency::Low,
            });
        }
        notes
    }

    pub fn on_failure(&mut self, error: &str) -> Vec<Note> {
        self.failures += 1;
        if self.failures < FAILURES_BEFORE_ALERT || self.lost_notified {
            return vec![];
        }
        self.lost_notified = true;
        if !self.preferences.enabled {
            return vec![];
        }
        let language = baradwatchu_messages::configured_language();
        vec![Note {
            title: baradwatchu_messages::message("tray.notice.agent_lost", language).into(),
            body: baradwatchu_messages::message("tray.notice.retry", language)
                .replace("{error}", error),
            urgency: Urgency::Normal,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u64, severity: Severity, repeated: bool) -> Event {
        Event {
            id,
            severity,
            title: format!("e{id}"),
            body: String::new(),
            repeated,
        }
    }

    fn snapshot(latest: u64, events: Vec<Event>, preferences: Preferences) -> Snapshot {
        Snapshot {
            agent_version: "0.0.1".into(),
            latest_event_id: latest,
            events,
            preferences,
            pending_consents: vec![],
            last_audit: None,
            last_audit_error: None,
        }
    }

    #[test]
    fn first_snapshot_sets_cursor_without_replaying_backlog() {
        let mut notifier = Notifier::default();
        let notes = notifier.on_snapshot(&snapshot(
            50,
            vec![event(50, Severity::Critical, false)],
            Preferences::default(),
        ));
        assert!(notes.is_empty());
        assert_eq!(notifier.cursor(), Some(50));
        let notes = notifier.on_snapshot(&snapshot(
            60,
            vec![event(60, Severity::Warning, false)],
            Preferences::default(),
        ));
        assert_eq!(notes.len(), 1);
        // Same event delivered again (e.g. overlapping polls) is not shown twice.
        assert!(notifier
            .on_snapshot(&snapshot(
                60,
                vec![event(60, Severity::Warning, false)],
                Preferences::default()
            ))
            .is_empty());
    }

    #[test]
    fn disabled_and_informative_preferences_are_respected() {
        let off = Preferences {
            enabled: false,
            informative: true,
        };
        let quiet = Preferences {
            enabled: true,
            informative: false,
        };
        assert!(!wants(&event(1, Severity::Critical, false), off));
        assert!(
            wants(&event(1, Severity::Action, false), off),
            "consent requests are never silenced"
        );
        assert!(!wants(&event(1, Severity::Info, false), quiet));
        assert!(
            !wants(&event(1, Severity::Warning, true), quiet),
            "repeated anomalies are informative"
        );
        assert!(wants(&event(1, Severity::Warning, false), quiet));
        assert!(wants(
            &event(1, Severity::Info, false),
            Preferences::default()
        ));
    }

    #[test]
    fn bursts_are_coalesced_most_urgent_first() {
        let mut notifier = Notifier::default();
        notifier.on_snapshot(&snapshot(0, vec![], Preferences::default()));
        let events = (1..=6)
            .map(|id| {
                event(
                    id,
                    if id == 6 {
                        Severity::Action
                    } else {
                        Severity::Info
                    },
                    false,
                )
            })
            .collect();
        let notes = notifier.on_snapshot(&snapshot(6, events, Preferences::default()));
        assert_eq!(notes.len(), MAX_NOTES_PER_POLL + 1);
        assert_eq!(notes[0].title, "e6");
        assert!(notes.last().unwrap().body.contains("Altri 3"));
    }

    #[test]
    fn communication_loss_is_notified_once_and_recovery_once() {
        let mut notifier = Notifier::default();
        notifier.on_snapshot(&snapshot(0, vec![], Preferences::default()));
        assert!(
            notifier.on_failure("timeout").is_empty(),
            "a single failure is tolerated"
        );
        assert_eq!(notifier.on_failure("timeout").len(), 1);
        assert!(
            notifier.on_failure("timeout").is_empty(),
            "no repeated alerts"
        );
        let notes = notifier.on_snapshot(&snapshot(0, vec![], Preferences::default()));
        assert_eq!(notes.len(), 1);
        assert!(notes[0].title.contains("di nuovo raggiungibile"));
        assert!(notifier
            .on_snapshot(&snapshot(0, vec![], Preferences::default()))
            .is_empty());
    }

    #[test]
    fn communication_alerts_follow_master_switch() {
        let mut notifier = Notifier::default();
        notifier.on_snapshot(&snapshot(
            0,
            vec![],
            Preferences {
                enabled: false,
                informative: true,
            },
        ));
        notifier.on_failure("x");
        assert!(notifier.on_failure("x").is_empty());
    }

    #[test]
    fn health_orders_states_and_summary_never_claims_certification() {
        assert_eq!(health(None), Health::Unreachable);
        let mut s = snapshot(0, vec![], Preferences::default());
        assert_eq!(health(Some(&s)), Health::NoAudit);
        s.last_audit = Some(AuditDigest {
            pass: 9,
            ..AuditDigest::default()
        });
        assert_eq!(health(Some(&s)), Health::Ok);
        let text = summary(Some(&s), None, 0);
        assert!(text.contains("non è una certificazione"));
        s.last_audit.as_mut().unwrap().warn = 1;
        assert_eq!(health(Some(&s)), Health::Anomalies);
        s.last_audit.as_mut().unwrap().integrity_issues = vec!["CUSTOM-001".into()];
        assert_eq!(health(Some(&s)), Health::Critical);
        assert!(summary(Some(&s), None, 0).contains("CUSTOM-001"));
        s.pending_consents.push(Consent {
            request_id: "a".into(),
            prompt: String::new(),
            remaining_seconds: 5,
        });
        assert_eq!(health(Some(&s)), Health::Attention);
    }

    #[test]
    fn parses_agent_snapshot_contract() {
        let text = r#"{"schemaVersion":"baradwatchu.companion-state.v1","agentVersion":"0.0.1","latestEventId":7,
          "events":[{"id":7,"atUnixMs":7,"kind":"AUDIT_COMPLETED","severity":"INFO","title":"t","body":"b","repeated":false}],
          "preferences":{"schemaVersion":"baradwatchu.notifications.v1","enabled":true,"informative":false},
          "pendingConsents":[{"schemaVersion":"x","requestId":"r","prompt":"p","effect":"e","remainingSeconds":3}],
          "lastAudit":{"completedAtUnixMs":1,"overallStatus":"PASS","pass":1,"fail":0,"warn":0,"error":0,"other":0,
            "integrityIssues":[],"executionErrors":[],"anomalies":[],"customChecks":0,"customNotPass":0}}"#;
        let snapshot = parse_snapshot(text).unwrap();
        assert_eq!(snapshot.latest_event_id, 7);
        assert!(!snapshot.preferences.informative);
        assert_eq!(snapshot.pending_consents[0].remaining_seconds, 3);
        assert!(parse_snapshot("null").is_err());
    }
}
