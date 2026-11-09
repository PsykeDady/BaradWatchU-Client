//! Shared language selection and message catalog used by the agent and tray.
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf, sync::OnceLock};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    #[default]
    System,
    Italian,
    English,
}

impl Language {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "system" => Some(Self::System),
            "it" => Some(Self::Italian),
            "en" => Some(Self::English),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::System => system_language().code(),
            Self::Italian => "it_IT",
            Self::English => "en_EN",
        }
    }

    pub fn effective(self) -> Self {
        match self {
            Self::System => system_language(),
            language => language,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LanguagePreference {
    pub schema_version: String,
    pub language: Language,
}

impl Default for LanguagePreference {
    fn default() -> Self {
        Self {
            schema_version: "baradwatchu.language.v1".into(),
            language: Language::System,
        }
    }
}

pub fn configuration_directory() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("baradwatchu"))
    } else if let Some(path) = std::env::var_os("XDG_CONFIG_HOME").filter(|path| !path.is_empty()) {
        Some(PathBuf::from(path).join("baradwatchu"))
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join(".config/baradwatchu"))
    }
}

pub fn configured_language() -> Language {
    let preference = configuration_directory()
        .and_then(|dir| fs::read_to_string(dir.join("language.json")).ok())
        .and_then(|text| serde_json::from_str::<LanguagePreference>(&text).ok())
        .filter(|preference| preference.schema_version == "baradwatchu.language.v1")
        .unwrap_or_default();
    preference.language
}

/// Detect the user's interface locale. Missing, neutral, or unsupported locales fall back
/// to English (`en_EN`).
pub fn system_language() -> Language {
    static DETECTED: OnceLock<Language> = OnceLock::new();
    *DETECTED.get_or_init(detect_system_language)
}

fn detect_system_language() -> Language {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
        return if unsafe { GetUserDefaultUILanguage() } & 0x03ff == 0x10 {
            Language::Italian
        } else {
            Language::English
        };
    }
    #[cfg(target_os = "macos")]
    {
        let languages = std::process::Command::new("/usr/bin/defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
        if let Some(language) = languages.as_deref().and_then(language_from_apple_languages) {
            return language;
        }
        let locale = std::process::Command::new("/usr/bin/defaults")
            .args(["read", "-g", "AppleLocale"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
        if let Some(language) = locale.as_deref().and_then(language_from_locale) {
            return language;
        }
    }
    // Ignore C/POSIX: those are often set by wrappers and do not describe the user's
    // desktop language. Continue through the remaining locale variables instead.
    for locale in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok())
    {
        for candidate in locale.split(':') {
            if let Some(language) = language_from_locale(candidate) {
                return language;
            }
        }
    }
    #[allow(unreachable_code)]
    Language::English
}

#[cfg(target_os = "macos")]
fn language_from_apple_languages(value: &str) -> Option<Language> {
    value
        .split(|character: char| !character.is_ascii_alphabetic())
        .filter(|candidate| !candidate.is_empty())
        .find_map(language_from_locale)
}

fn language_from_locale(locale: &str) -> Option<Language> {
    let language = locale.trim().split(['_', '-', '.', '@']).next()?;
    if language.eq_ignore_ascii_case("it") {
        Some(Language::Italian)
    } else if language.eq_ignore_ascii_case("en") {
        Some(Language::English)
    } else {
        None
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct LocaleCatalog {
    messages: HashMap<String, String>,
    diagnostics: HashMap<String, String>,
    diagnostic_templates: HashMap<String, String>,
    diagnostic_labels: HashMap<String, String>,
    requirements: HashMap<String, RequirementText>,
    cli_help: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RequirementText {
    name: String,
    description: String,
}

fn locale_catalog(language: Language) -> &'static LocaleCatalog {
    static ITALIAN: OnceLock<LocaleCatalog> = OnceLock::new();
    static ENGLISH: OnceLock<LocaleCatalog> = OnceLock::new();
    let (slot, data) = if language.effective() == Language::Italian {
        (&ITALIAN, include_str!("../locales/it_IT.json"))
    } else {
        (&ENGLISH, include_str!("../locales/en_EN.json"))
    };
    slot.get_or_init(|| serde_json::from_str(data).unwrap_or_default())
}

/// Shared locale data is embedded from one readable JSON file per locale. If a file
/// cannot be parsed or a key is missing, the stable key itself is shown as the label.
pub fn message(key: &str, language: Language) -> &str {
    locale_catalog(language)
        .messages
        .get(key)
        .map(String::as_str)
        .unwrap_or(key)
}

fn diagnostic_template(key: &str, language: Language) -> &str {
    locale_catalog(language)
        .diagnostic_templates
        .get(key)
        .map(String::as_str)
        .unwrap_or(key)
}

fn render(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut output = template.to_owned();
    for (key, value) in replacements {
        output = output.replace(&format!("{{{key}}}"), value);
    }
    output
}

fn range_values<'a>(value: &'a str, suffix: &str) -> Option<(&'a str, &'a str)> {
    let value = value.strip_suffix(suffix)?;
    let (minimum, maximum) = value.split_once(" e ")?;
    Some((minimum.trim(), maximum.trim()))
}

fn invalid_text_max(value: &str) -> Option<&str> {
    let value = value.strip_prefix("testo non valido (1-")?;
    let (maximum, tail) = value.split_once(' ')?;
    (tail == "caratteri, senza caratteri di controllo)").then_some(maximum)
}

/// Translate operational diagnostics at their presentation boundary. Static translations
/// live in the locale JSON; this function only identifies dynamic source patterns and fills
/// their localized templates. Unknown diagnostics remain intact.
pub fn localize_diagnostic(source: &str, language: Language) -> String {
    let catalog = locale_catalog(language);
    if let Some(value) = catalog.diagnostics.get(source) {
        return value.clone();
    }

    if let Some((path, _)) = source.split_once(" non è gestito da BaradWatchU: rimuovilo a mano") {
        return render(
            diagnostic_template("not_managed", language),
            &[("path", path)],
        );
    }

    for (prefix, key) in [
        ("Avvio automatico non modificato: ", "autostart_not_updated"),
        ("avvio della tray non riuscito: ", "tray_start_failed"),
        ("la tray ha restituito un errore: ", "tray_returned_error"),
        ("non determinabile (", "undetermined"),
        (
            "configurazione tema non leggibile: ",
            "theme_config_unreadable",
        ),
        ("configurazione tema non valida: ", "theme_config_invalid"),
        ("contrasto accento/sfondo ", "accent_contrast"),
        ("report JSON non leggibile: ", "report_json_unreadable"),
        ("lettura report JSON non riuscita: ", "report_read_failed"),
        ("report JSON non valido: ", "report_json_invalid"),
        ("salvataggio PDF non riuscito: ", "pdf_save_failed"),
        ("logo non leggibile: ", "logo_unreadable"),
        ("PNG non valido: ", "png_invalid"),
    ] {
        if let Some(detail) = source.strip_prefix(prefix) {
            return render(diagnostic_template(key, language), &[("detail", detail)]);
        }
    }

    if let Some(limit) = source.strip_prefix("dimensioni logo oltre il limite di ") {
        return render(
            diagnostic_template("logo_dimensions", language),
            &[("limit", limit)],
        );
    }
    if source.starts_with("avvio della tray non riuscito") {
        return diagnostic_template("tray_start_failed_short", language).to_owned();
    }

    for (prefix, key) in [
        ("agente non trovato in ", "agent_not_found_in"),
        ("impossibile rimuovere ", "cannot_remove"),
        ("impossibile creare ", "cannot_create"),
        ("impossibile scrivere ", "cannot_write"),
    ] {
        if let Some(path) = source.strip_prefix(prefix) {
            return render(diagnostic_template(key, language), &[("path", path)]);
        }
    }

    if let Some((context, detail)) = source.split_once(": ") {
        if let Some(translated_context) = catalog.diagnostics.get(context) {
            return format!("{translated_context}: {detail}");
        }
    }

    for prefix in ["Unknown requirement: ", "Requisito sconosciuto: "] {
        if let Some(id) = source.strip_prefix(prefix) {
            return render(
                diagnostic_template("unknown_requirement", language),
                &[("id", id)],
            );
        }
    }
    if let Some(version) = source
        .strip_prefix("schemaVersion deve essere \"")
        .and_then(|value| value.strip_suffix('"'))
    {
        return render(
            diagnostic_template("schema_version", language),
            &[("version", version)],
        );
    }
    if let Some((id, folder)) = source
        .strip_prefix("id \"")
        .and_then(|value| value.split_once("\" diverso dal nome della cartella \""))
        .and_then(|(id, folder)| folder.strip_suffix('"').map(|folder| (id, folder)))
    {
        return render(
            diagnostic_template("folder_id_mismatch", language),
            &[("id", id), ("folder", folder)],
        );
    }
    if let Some((_, path)) = source.split_once(" non trovato: ") {
        if source.starts_with("Tool") {
            return render(
                diagnostic_template("tool_not_found_path", language),
                &[("path", path)],
            );
        }
    }
    if let Some(tool) = source
        .strip_prefix("Tool ")
        .and_then(|value| value.strip_suffix(" non trovato"))
    {
        return render(
            diagnostic_template("tool_not_found_name", language),
            &[("tool", tool)],
        );
    }
    for (prefix, key, field) in [
        ("Tool missing for ", "tool_missing_for", "id"),
        ("Unsafe tool path for ", "unsafe_tool_path_for", "id"),
        (
            "Trusted hash mismatch in configuration for ",
            "trusted_hash_mismatch",
            "id",
        ),
    ] {
        if let Some(id) = source.strip_prefix(prefix) {
            return render(diagnostic_template(key, language), &[(field, id)]);
        }
    }
    if let Some((from, to)) = source
        .strip_prefix("Cannot migrate ")
        .and_then(|value| value.split_once(" to "))
    {
        return render(
            diagnostic_template("cannot_migrate", language),
            &[("from", from), ("to", to)],
        );
    }
    if let Some(path) = source.strip_prefix("Cannot remove ") {
        return render(
            diagnostic_template("cannot_remove", language),
            &[("path", path)],
        );
    }
    if let Some(detail) = source.strip_prefix("configuration.json non valido: ") {
        return render(
            diagnostic_template("configuration_invalid", language),
            &[("detail", &localize_diagnostic(detail, language))],
        );
    }
    if let Some(range) = source.strip_prefix("timeoutSeconds deve essere compreso tra ") {
        if let Some((minimum, maximum)) = range_values(range, " secondi") {
            return render(
                diagnostic_template("timeout_range", language),
                &[("min", minimum), ("max", maximum)],
            );
        }
    }
    if let Some(range) = source.strip_prefix("La scadenza deve essere tra ") {
        if let Some((minimum, maximum)) = range_values(range, " secondi") {
            return render(
                diagnostic_template("expiry_range", language),
                &[("min", minimum), ("max", maximum)],
            );
        }
    }
    if let Some(maximum) = invalid_text_max(source) {
        return render(
            diagnostic_template("invalid_text", language),
            &[("max", maximum)],
        );
    }
    if let Some((label, detail)) = source.split_once(": ") {
        if let Some(maximum) = invalid_text_max(detail) {
            let localized_label = catalog
                .diagnostic_labels
                .get(label)
                .map(String::as_str)
                .unwrap_or(label);
            let text = render(
                diagnostic_template("invalid_text", language),
                &[("max", maximum)],
            );
            return format!("{localized_label}: {text}");
        }
    }
    if let Some((id, reason)) = source
        .strip_prefix("Invalid check configuration for ")
        .and_then(|value| value.split_once(": "))
    {
        return render(
            diagnostic_template("invalid_check_configuration", language),
            &[
                ("id", id),
                ("reason", &localize_diagnostic(reason, language)),
            ],
        );
    }
    source.to_owned()
}

pub fn dashboard_catalog(
    language: Language,
) -> std::collections::BTreeMap<&'static str, &'static str> {
    const KEYS: &[&str] = &[
        "ui.nav.status",
        "ui.nav.custom",
        "ui.nav.notifications",
        "ui.nav.settings",
        "ui.audit.run",
        "ui.audit.running",
        "ui.retry",
        "ui.loading",
        "ui.intro.status",
        "ui.intro.copy",
        "ui.summary.latest",
        "ui.summary.historical",
        "ui.summary.none",
        "ui.summary.waiting",
        "ui.metric.pass",
        "ui.metric.fail",
        "ui.metric.warn",
        "ui.metric.error",
        "ui.metric.other",
        "ui.summary.empty",
        "ui.summary.back",
        "ui.catalog",
        "ui.requirements",
        "ui.filter",
        "ui.search",
        "ui.catalog.missing",
        "ui.filters.none",
        "ui.filters.show_all",
        "ui.tag.custom",
        "ui.tag.replaced_by",
        "ui.tag.invalid",
        "ui.tag.modified",
        "ui.tag.disabled",
        "ui.tag.pending",
        "ui.details.settings",
        "ui.details.result",
        "ui.details.no_result",
        "ui.details.current_settings",
        "ui.check.now",
        "ui.history",
        "ui.history.clear",
        "ui.history.empty",
        "ui.settings.language",
        "ui.settings.language_active",
        "ui.settings.language_saved",
        "ui.status.pass",
        "ui.status.fail",
        "ui.status.warn",
        "ui.status.error",
        "ui.status.disabled",
        "ui.status.na",
        "ui.overall.pass",
        "ui.overall.fail",
        "ui.overall.warn",
        "ui.overall.error",
        "ui.priority.highest",
        "ui.priority.high",
        "ui.priority.medium",
        "ui.priority.low",
        "ui.priority.optional",
        "language.system",
        "language.italian",
        "language.english",
        "ui.custom.eyebrow",
        "ui.custom.intro",
        "ui.custom.rescan",
        "ui.custom.new",
        "ui.custom.new_title",
        "ui.custom.warning",
        "ui.custom.id_help",
        "ui.custom.description_placeholder",
        "ui.custom.timeout_help",
        "ui.custom.file_help",
        "ui.custom.args_help",
        "ui.custom.advanced",
        "ui.custom.no_clone",
        "ui.custom.no_override",
        "ui.custom.override_help",
        "ui.custom.cancel",
        "ui.custom.importing",
        "ui.custom.import",
        "ui.custom.installed",
        "ui.custom.mine",
        "ui.custom.ignored",
        "ui.custom.none",
        "ui.custom.create_hint",
        "ui.custom.create_hint_end",
        "ui.custom.invalid",
        "ui.custom.changed",
        "ui.custom.unreadable",
        "ui.custom.accept",
        "ui.custom.upload",
        "ui.custom.restore",
        "ui.custom.delete",
        "ui.custom.guide",
        "ui.custom.output_rule",
        "ui.custom.hash_rule",
        "ui.custom.run_rule",
        "ui.custom.clone_from",
        "ui.custom.replace",
        "ui.custom.description",
        "ui.notifications.eyebrow",
        "ui.notifications.intro",
        "ui.notifications.preferences",
        "ui.notifications.audit",
        "ui.notifications.informative",
        "ui.notifications.consent_hint",
        "ui.notifications.events",
        "ui.notifications.no_events",
        "ui.notifications.repeated",
        "ui.notifications.consent",
        "ui.notifications.consent_info",
        "ui.notifications.simulate",
        "ui.notifications.no_requests",
        "ui.settings.local",
        "ui.settings.intro",
        "ui.settings.unavailable",
        "ui.settings.tray",
        "ui.settings.startup",
        "ui.settings.tray_missing",
        "ui.settings.notifications",
        "ui.settings.pdf_theme",
        "ui.settings.save_theme",
        "ui.settings.local_data",
        "ui.settings.folders",
        "ui.settings.tray_active",
        "ui.settings.tray_inactive",
        "ui.settings.tray_unknown",
        "ui.settings.tray_not_installed",
        "ui.settings.autostart_on",
        "ui.settings.autostart_off",
        "ui.settings.tray_error",
        "ui.brand.aria",
        "ui.sections",
        "ui.close",
        "ui.all",
        "ui.refresh",
        "ui.platform",
        "ui.history.loading",
        "ui.history.viewing",
        "ui.history.limit",
        "ui.history.loading_short",
        "ui.history.disk",
        "ui.history.delete_aria",
        "ui.history.delete_title",
        "ui.history.ok",
        "ui.history.fail",
        "ui.history.warn",
        "ui.history.errors",
        "ui.tag.replaces",
        "ui.requirement.result_date",
        "ui.requirement.enabled",
        "ui.requirement.disabled",
        "ui.requirement.manage_custom",
        "ui.requirement.advanced",
        "ui.requirement.parameters_hint",
        "ui.requirement.parameters_for",
        "ui.requirement.save_parameters",
        "ui.requirement.technical",
        "ui.field.origin",
        "ui.field.builtin",
        "ui.field.custom",
        "ui.field.tool",
        "ui.field.arguments",
        "ui.field.timeout",
        "ui.field.integrity",
        "ui.field.sha_expected",
        "ui.field.sha_actual",
        "ui.field.executed",
        "ui.field.integrity_at_run",
        "ui.field.provenance",
        "ui.field.legacy_report",
        "ui.value.unavailable",
        "ui.eyebrow.local_archive",
        "ui.eyebrow.local_history",
        "ui.pdf.open",
        "ui.pdf.saved",
        "ui.pdf.warning",
        "ui.pdf.failed",
        "ui.pdf.client",
        "ui.providers.title",
        "ui.providers.required",
        "ui.providers.optional",
        "ui.installation.verified",
        "ui.installation.mismatch",
        "ui.tag.configured_by",
        "ui.requirement.override_hint",
        "ui.custom.local_values",
        "ui.custom.configuration_only",
        "ui.custom.obsolete_settings",
        "ui.custom.name_placeholder",
        "ui.custom.check_now",
        "ui.custom.tool",
        "ui.custom.integrity",
        "ui.custom.ignored_prefix",
        "ui.notifications.state",
        "ui.notifications.expires",
        "ui.notifications.simulated",
        "ui.notifications.server",
        "ui.notifications.account",
        "ui.notifications.device",
        "ui.notifications.result",
        "ui.settings.tray_status_error",
        "ui.settings.tray_explanation",
        "ui.settings.notifications_hint",
        "pdf.warning.text_contrast",
        "pdf.warning.accent_contrast",
        "ui.settings.pdf_hint",
        "ui.settings.configuration",
        "ui.settings.logo_path",
        "ui.settings.logo_placeholder",
        "ui.settings.logo_help",
        "ui.settings.text_color",
        "ui.settings.background",
        "ui.settings.accent",
        "ui.settings.folders.configuration",
        "ui.settings.folders.custom",
        "ui.settings.folders.events",
        "ui.settings.folders.history",
        "ui.settings.folders.runtime",
        "ui.settings.history_hint",
        "ui.settings.about",
        "ui.settings.version",
        "ui.settings.system",
        "ui.settings.installation",
        "ui.settings.uninstall_hint",
        "ui.footer.local_data",
        "ui.footer.refresh",
        "ui.custom.close_form",
        "ui.integrity.verified",
        "ui.integrity.mismatch",
        "ui.integrity.unknown",
        "ui.severity.info",
        "ui.severity.warning",
        "ui.severity.critical",
        "ui.severity.action",
        "ui.consent.pending",
        "ui.consent.accepted",
        "ui.consent.rejected",
        "ui.consent.expired",
        "ui.date.unavailable",
        "ui.save.notifications",
        "ui.save.pdf_theme",
        "ui.error.session_missing",
        "ui.error.session_invalid",
        "ui.error.communication",
        "ui.error.json_parameters",
        "ui.error.arguments",
        "ui.error.timeout",
        "ui.error.tool_size",
        "ui.error.consent_tray",
        "ui.error.consent_cli",
        "ui.custom.result_summary",
        "ui.custom.import_success",
        "ui.custom.update_success",
        "ui.custom.accept_success",
        "ui.custom.restore_success",
        "ui.custom.delete_success",
        "ui.custom.import_confirm",
        "ui.custom.update_confirm",
        "ui.custom.accept_confirm",
        "ui.custom.delete_confirm",
        "ui.history.delete_confirm",
        "ui.history.clear_confirm",
        "ui.history.removed",
        "ui.audit.check_progress",
        "ui.audit.check_done",
        "ui.audit.run_progress",
        "ui.audit.run_done",
        "ui.audit.priority_saved",
        "ui.audit.params_saved",
        "ui.audit.setting",
        "ui.audit.enabled",
        "ui.audit.disabled",
        "ui.history.open_error",
        "ui.custom.tool",
        "ui.custom.integrity",
        "ui.section.requirements",
        "ui.section.latest",
        "ui.section.history",
        "ui.section.notifications",
        "ui.section.settings",
        "ui.alert.custom_issues",
        "ui.alert.pending_requests",
        "ui.custom.restore_extra",
        "ui.pdf.open_error",
        "ui.error.agent_unreachable",
        "ui.brand.subtitle",
        "ui.custom.guide.folder",
        "ui.custom.guide.output",
        "ui.custom.guide.states",
        "ui.custom.guide.details",
        "ui.custom.guide.hash",
        "ui.custom.guide.hash_changed",
        "ui.custom.guide.run",
        "ui.custom.folder",
        "ui.custom.guide.sample_summary",
        "ui.custom.guide.sample_detail",
        "ui.warning",
        "ui.timeout",
        "ui.custom.tool_file",
        "ui.custom.arguments",
        "ui.custom.name",
        "ui.custom.priority",
    ];
    KEYS.iter()
        .map(|key| (*key, message(key, language)))
        .collect()
}

pub fn requirement_metadata(id: &str, language: Language) -> Option<(&'static str, &'static str)> {
    locale_catalog(language)
        .requirements
        .get(id)
        .map(|metadata| (metadata.name.as_str(), metadata.description.as_str()))
}

pub fn agent_help(language: Language, version: &str) -> String {
    let template = &locale_catalog(language).cli_help;
    if template.is_empty() {
        "cli.help".to_owned()
    } else {
        template.replace("{version}", version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_default_recognizes_italian_and_falls_back_to_english() {
        assert_eq!(Language::parse("system"), Some(Language::System));
        assert_eq!(Language::parse("it"), Some(Language::Italian));
        assert_eq!(Language::parse("en"), Some(Language::English));
        assert_eq!(Language::parse("fr"), None);
        assert_eq!(Language::Italian.code(), "it_IT");
        assert_eq!(Language::English.code(), "en_EN");
    }

    #[test]
    fn unknown_message_is_visibly_flagged() {
        assert_eq!(message("missing.key", Language::English), "missing.key");
    }
}
