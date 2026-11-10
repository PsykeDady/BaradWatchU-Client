//! Offline PDF reports. The renderer accepts a saved audit JSON path, so the Client and a future
//! Server can share the same report contract without coupling PDF layout to audit execution.
use crate::requirements::{
    self as req, AuditReport, CliError, DisabledRequirement, ProviderResult, ResultRecord,
    ResultStatus,
};
use flate2::{write::ZlibEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

const THEME_SCHEMA: &str = "baradwatchu.report-theme.v1";
const DEFAULT_THEME_ID: &str = "default";
const THEME_SELECTION_SCHEMA: &str = "baradwatchu.report-theme-selection.v1";
const TEMPLATE_VERSION: &str = "1.3.0";
const PAGE_W: f32 = 595.28;
const PAGE_H: f32 = 841.89;
const MARGIN: f32 = 38.0;
const LOGO_W: f32 = PAGE_W / 4.0;
const LOGO_H: f32 = PAGE_H / 6.0;
const MAX_LOGO_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOGO_DIMENSION: u32 = 4096;
const REPORT_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReportTheme {
    pub schema_version: String,
    /// Optional PNG/JPEG path. `null` uses the transparent built-in BaradWatch mark.
    pub logo_path: Option<String>,
    /// Main text color. Defaults to black.
    pub primary_color: String,
    /// Page/table background color. Defaults to white.
    pub secondary_color: String,
    /// Rules, table separators and highlights. Defaults to BaradWatch red.
    pub accent_color: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThemeFile {
    id: String,
    name: String,
    #[serde(flatten)]
    theme: ReportTheme,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThemeOption {
    id: String,
    name: String,
    logo_path: Option<String>,
    primary_color: String,
    secondary_color: String,
    accent_color: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThemeCatalog {
    schema_version: &'static str,
    selected_theme_id: String,
    themes: Vec<ThemeOption>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ThemeSelection {
    theme: String,
}

impl Default for ReportTheme {
    fn default() -> Self {
        Self {
            schema_version: THEME_SCHEMA.into(),
            logo_path: None,
            primary_color: "#111111".into(),
            secondary_color: "#FFFFFF".into(),
            accent_color: "#B3262D".into(),
        }
    }
}

fn theme_path() -> Result<PathBuf, CliError> {
    Ok(req::state_dir()?.join("report-theme.json"))
}

fn themes_dir() -> Result<PathBuf, CliError> {
    Ok(req::state_dir()?.join("themes"))
}

fn valid_theme_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id != DEFAULT_THEME_ID
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        })
}

fn theme_catalog() -> Result<ThemeCatalog, String> {
    let mut themes = vec![ThemeOption {
        id: DEFAULT_THEME_ID.into(),
        name: "BaradWatchU".into(),
        logo_path: None,
        primary_color: "#111111".into(),
        secondary_color: "#FFFFFF".into(),
        accent_color: "#B3262D".into(),
    }];
    let directory = themes_dir().map_err(|error| error.0)?;
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let entries = fs::read_dir(&directory)
                .map_err(|error| format!("cartella temi non leggibile: {error}"))?;
            for entry in entries {
                let entry = entry.map_err(|error| format!("elenco temi non leggibile: {error}"))?;
                let path = entry.path();
                if path
                    .extension()
                    .map_or(true, |extension| extension != "json")
                {
                    continue;
                }
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|error| format!("file tema non leggibile: {error}"))?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > 16 * 1024
                {
                    continue;
                }
                let bytes =
                    fs::read(&path).map_err(|error| format!("file tema non leggibile: {error}"))?;
                let Ok(file) = serde_json::from_slice::<ThemeFile>(&bytes) else {
                    continue;
                };
                let filename = path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default();
                if !valid_theme_id(&file.id)
                    || file.id != filename
                    || file.name.trim().is_empty()
                    || file.name.len() > 128
                    || validate_theme(&file.theme).is_err()
                {
                    continue;
                }
                themes.push(ThemeOption {
                    id: file.id,
                    name: file.name,
                    logo_path: file.theme.logo_path,
                    primary_color: file.theme.primary_color,
                    secondary_color: file.theme.secondary_color,
                    accent_color: file.theme.accent_color,
                });
            }
        }
        Ok(_) => return Err("la cartella temi non è sicura".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cartella temi non leggibile: {error}")),
    }
    themes.sort_by(|left, right| left.id.cmp(&right.id));
    themes.sort_by_key(|theme| theme.id != DEFAULT_THEME_ID);
    let selection_path = theme_path().map_err(|error| error.0)?;
    let selected_theme_id = match fs::symlink_metadata(&selection_path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 16 * 1024 =>
        {
            let bytes = fs::read(&selection_path)
                .map_err(|error| format!("selezione tema non leggibile: {error}"))?;
            let selection: ThemeSelection = serde_json::from_slice(&bytes)
                .map_err(|_| "file report-theme.json non valido".to_owned())?;
            if selection.theme != DEFAULT_THEME_ID && !valid_theme_id(&selection.theme) {
                return Err("ID del tema selezionato non valido".into());
            }
            selection.theme
        }
        Ok(_) => return Err("file di selezione tema non sicuro o oltre 16 KiB".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DEFAULT_THEME_ID.into(),
        Err(error) => return Err(format!("selezione tema non leggibile: {error}")),
    };
    Ok(ThemeCatalog {
        schema_version: THEME_SELECTION_SCHEMA,
        selected_theme_id,
        themes,
    })
}

fn selected_theme() -> Result<ReportTheme, String> {
    let catalog = theme_catalog()?;
    if catalog.selected_theme_id == DEFAULT_THEME_ID {
        return Ok(ReportTheme::default());
    }
    let Some(option) = catalog
        .themes
        .iter()
        .find(|theme| theme.id == catalog.selected_theme_id)
    else {
        return Err(format!(
            "tema report selezionato non disponibile: {}",
            catalog.selected_theme_id
        ));
    };
    if option.id == DEFAULT_THEME_ID {
        return Ok(ReportTheme::default());
    }
    let path = themes_dir()
        .map_err(|error| error.0)?
        .join(format!("{}.json", option.id));
    let bytes = fs::read(&path).map_err(|_| {
        format!(
            "tema report selezionato non trovato: {}",
            catalog.selected_theme_id
        )
    })?;
    let file: ThemeFile = serde_json::from_slice(&bytes)
        .map_err(|_| "file del tema selezionato non valido".to_owned())?;
    validate_theme(&file.theme).map_err(|error| format!("tema selezionato non valido: {error}"))?;
    Ok(file.theme)
}

pub(crate) fn run_theme(args: &[std::ffi::OsString]) -> Result<req::CliOutput, CliError> {
    let words: Vec<_> = args
        .iter()
        .map(|arg| {
            arg.to_str()
                .ok_or_else(|| CliError("argomento tema non valido".into()))
        })
        .collect::<Result<_, _>>()?;
    match words.as_slice() {
        ["list"] => {
            let catalog = theme_catalog().map_err(CliError)?;
            let output = catalog
                .themes
                .iter()
                .map(|theme| {
                    format!(
                        "{}{} — {}",
                        if theme.id == catalog.selected_theme_id {
                            "* "
                        } else {
                            "  "
                        },
                        theme.id,
                        theme.name
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(req::CliOutput {
                text: format!("{output}\n"),
                code: 0,
            })
        }
        ["use", id] => {
            let catalog = theme_catalog().map_err(CliError)?;
            if !catalog.themes.iter().any(|theme| theme.id == *id) {
                return Err(CliError(format!("tema non trovato: {id}")));
            }
            let path = theme_path()?;
            let parent = path
                .parent()
                .ok_or_else(|| CliError("percorso tema non valido".into()))?;
            req::ensure_private_dir(parent)?;
            req::atomic_json(&path, &serde_json::json!({"theme": id}))?;
            Ok(req::CliOutput {
                text: format!("Tema report selezionato: {id}\n"),
                code: 0,
            })
        }
        _ => Err(CliError(
            "Uso: report-theme list | report-theme use ID".into(),
        )),
    }
}

fn read_theme() -> Result<ReportTheme, String> {
    selected_theme()
}

fn parse_color(value: &str) -> Result<[u8; 3], String> {
    let hex = value.strip_prefix('#').ok_or("usa il formato #RRGGBB")?;
    if hex.len() != 6 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("usa il formato #RRGGBB".into());
    }
    let channel = |from| {
        u8::from_str_radix(&hex[from..from + 2], 16).map_err(|_| "colore non valido".to_owned())
    };
    Ok([channel(0)?, channel(2)?, channel(4)?])
}

fn validate_theme(theme: &ReportTheme) -> Result<(), String> {
    if theme.schema_version != THEME_SCHEMA {
        return Err("schemaVersion non supportata".into());
    }
    for color in [
        &theme.primary_color,
        &theme.secondary_color,
        &theme.accent_color,
    ] {
        parse_color(color)?;
    }
    if let Some(path) = &theme.logo_path {
        if path.len() > 4096 || path.trim().is_empty() {
            return Err("logoPath deve indicare un percorso valido".into());
        }
    }
    Ok(())
}

fn theme_warning(theme: &ReportTheme) -> Result<Option<String>, String> {
    let primary = parse_color(&theme.primary_color)?;
    let secondary = parse_color(&theme.secondary_color)?;
    let accent = parse_color(&theme.accent_color)?;
    let contrast = |a: [u8; 3], b: [u8; 3]| {
        let luminance = |color: [u8; 3]| {
            let channels = color.map(|channel| {
                let value = channel as f64 / 255.0;
                if value <= 0.04045 {
                    value / 12.92
                } else {
                    ((value + 0.055) / 1.055).powf(2.4)
                }
            });
            channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722
        };
        let (high, low) = {
            let x = luminance(a);
            let y = luminance(b);
            (x.max(y), x.min(y))
        };
        (high + 0.05) / (low + 0.05)
    };
    let text_ratio = contrast(primary, secondary);
    let accent_ratio = contrast(accent, secondary);
    let language = baradwatchu_messages::configured_language();
    let number = |value: f64| {
        let value = format!("{value:.1}");
        if language.effective() == baradwatchu_messages::Language::Italian {
            value.replace('.', ",")
        } else {
            value
        }
    };
    let mut warnings = Vec::new();
    if text_ratio < 4.5 {
        warnings.push(
            baradwatchu_messages::message("pdf.warning.text_contrast", language)
                .replace("{ratio}", &number(text_ratio))
                .replace(
                    "{minimum}",
                    if language.effective() == baradwatchu_messages::Language::Italian {
                        "4,5"
                    } else {
                        "4.5"
                    },
                ),
        );
    }
    if accent_ratio < 3.0 {
        warnings.push(
            baradwatchu_messages::message("pdf.warning.accent_contrast", language)
                .replace("{ratio}", &number(accent_ratio))
                .replace("{minimum}", "3"),
        );
    }
    Ok((!warnings.is_empty()).then(|| warnings.join("; ")))
}

pub(crate) fn dashboard_theme_json() -> Result<String, CliError> {
    let catalog = theme_catalog().map_err(CliError)?;
    req::output_json(&catalog)
}

pub(crate) fn dashboard_update_theme(text: &str) -> Result<String, CliError> {
    if text.len() > 16 * 1024 {
        return Err(CliError("Configurazione tema troppo grande".into()));
    }
    let update: ThemeSelection = serde_json::from_str(text)
        .map_err(|_| CliError("JSON selezione tema non valido".into()))?;
    let catalog = theme_catalog().map_err(CliError)?;
    if !catalog.themes.iter().any(|theme| theme.id == update.theme) {
        return Err(CliError(format!("tema non trovato: {}", update.theme)));
    }
    let path = theme_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| CliError("Percorso tema non valido".into()))?;
    req::ensure_private_dir(parent)?;
    req::atomic_json(&path, &update)?;
    dashboard_theme_json()
}

fn current_report_path(stamp: u64) -> Result<PathBuf, CliError> {
    Ok(req::history_dir()?
        .join("reports")
        .join(format!("{stamp}.json")))
}

fn pdf_path(stamp: u64) -> Result<PathBuf, CliError> {
    Ok(req::history_dir()?.join(format!("{stamp}.pdf")))
}

pub(crate) fn history_pdf(stamp: &str) -> Result<Vec<u8>, CliError> {
    let stamp = stamp
        .parse::<u64>()
        .map_err(|_| CliError("Identificativo audit non valido".into()))?;
    let path = pdf_path(stamp)?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| CliError("PDF non disponibile per questo audit".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32 * 1024 * 1024
    {
        return Err(CliError("File PDF non sicuro o troppo grande".into()));
    }
    fs::read(path).map_err(|_| CliError("PDF non leggibile".into()))
}

/// Generate a PDF by reading the persisted JSON. Any error is returned to the audit caller and
/// recorded in that audit; it never changes the audit's exit status.
pub(crate) struct GeneratedPdf {
    pub(crate) path: PathBuf,
    pub(crate) warning: Option<String>,
}

pub(crate) fn generate_for_audit(report: &AuditReport) -> Result<GeneratedPdf, String> {
    let json_path = current_report_path(report.completed_at_unix_ms).map_err(|error| error.0)?;
    let output_path = pdf_path(report.completed_at_unix_ms).map_err(|error| error.0)?;
    let warning = generate_from_json(&json_path, &output_path)?;
    Ok(GeneratedPdf {
        path: output_path,
        warning,
    })
}

fn generate_from_json(json_path: &Path, output_path: &Path) -> Result<Option<String>, String> {
    let metadata =
        fs::metadata(json_path).map_err(|error| format!("report JSON non leggibile: {error}"))?;
    if !metadata.is_file() || metadata.len() > REPORT_MAX_BYTES {
        return Err("report JSON non valido o troppo grande".into());
    }
    let json = fs::read(json_path)
        .map_err(|error| format!("lettura report JSON non riuscita: {error}"))?;
    let report: AuditReport = serde_json::from_slice(&json)
        .map_err(|error| format!("report JSON non valido: {error}"))?;
    let theme = read_theme()?;
    let warning = theme_warning(&theme)?;
    let theme_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&theme).map_err(|e| e.to_string())?)
    );
    let logo = match theme.logo_path.as_deref() {
        Some(path) => Some(load_logo(path)?),
        None => None,
    };
    let bytes = render_pdf(&report, &theme, &theme_hash, logo.as_ref())?;
    let parent = output_path.parent().ok_or("percorso PDF non valido")?;
    req::ensure_private_dir(parent).map_err(|error| error.0)?;
    write_atomic(output_path, &bytes)
        .map_err(|error| format!("salvataggio PDF non riuscito: {error}"))?;
    Ok(warning)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let temporary = parent.join(format!(".pdf-{}-{}.tmp", std::process::id(), req::now_ms()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

#[derive(Clone)]
enum Logo {
    RgbPng {
        width: u32,
        height: u32,
        rgb: Vec<u8>,
        alpha: Option<Vec<u8>>,
    },
    Jpeg {
        width: u32,
        height: u32,
        components: u8,
        bytes: Vec<u8>,
    },
}

fn load_logo(path: &str) -> Result<Logo, String> {
    let bytes = fs::read(path).map_err(|error| format!("logo non leggibile: {error}"))?;
    if bytes.len() > MAX_LOGO_BYTES {
        return Err("logo oltre il limite di 2 MiB".into());
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return decode_png(&bytes);
    }
    if bytes.starts_with(&[0xFF, 0xD8]) {
        return inspect_jpeg(bytes);
    }
    Err("formato logo non supportato: usa PNG o JPEG".into())
}

fn decode_png(bytes: &[u8]) -> Result<Logo, String> {
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|error| format!("PNG non valido: {error}"))?;
    let dimensions = (reader.info().width, reader.info().height);
    if dimensions.0 == 0
        || dimensions.1 == 0
        || dimensions.0 > MAX_LOGO_DIMENSION
        || dimensions.1 > MAX_LOGO_DIMENSION
    {
        return Err("dimensioni logo oltre il limite di 4096×4096".into());
    }
    let mut buffer = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or("dimensioni PNG non valide")?
    ];
    let info = reader
        .next_frame(&mut buffer)
        .map_err(|error| format!("PNG non valido: {error}"))?;
    if info.width == 0
        || info.height == 0
        || info.width > MAX_LOGO_DIMENSION
        || info.height > MAX_LOGO_DIMENSION
    {
        return Err("dimensioni logo oltre il limite di 4096×4096".into());
    }
    let source = &buffer[..info.buffer_size()];
    let channels = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::Rgb => 3,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err("PNG indicizzato non decodificato".into()),
    };
    let pixels = (info.width as usize)
        .checked_mul(info.height as usize)
        .ok_or("dimensioni PNG non valide")?;
    let mut rgb = Vec::with_capacity(pixels * 3);
    let mut alpha = Vec::new();
    for pixel in source.chunks_exact(channels) {
        match info.color_type {
            png::ColorType::Grayscale => rgb.extend_from_slice(&[pixel[0]; 3]),
            png::ColorType::Rgb => rgb.extend_from_slice(&pixel[..3]),
            png::ColorType::GrayscaleAlpha => {
                rgb.extend_from_slice(&[pixel[0]; 3]);
                alpha.push(pixel[1]);
            }
            png::ColorType::Rgba => {
                rgb.extend_from_slice(&pixel[..3]);
                alpha.push(pixel[3]);
            }
            png::ColorType::Indexed => unreachable!(),
        }
    }
    Ok(Logo::RgbPng {
        width: info.width,
        height: info.height,
        rgb,
        alpha: (!alpha.is_empty()).then_some(alpha),
    })
}

fn inspect_jpeg(bytes: Vec<u8>) -> Result<Logo, String> {
    let mut offset = 2;
    while offset + 4 <= bytes.len() {
        if bytes[offset] != 0xFF {
            offset += 1;
            continue;
        }
        while offset < bytes.len() && bytes[offset] == 0xFF {
            offset += 1;
        }
        if offset >= bytes.len() {
            break;
        }
        let marker = bytes[offset];
        offset += 1;
        if matches!(marker, 0xD8 | 0xD9 | 0x01 | 0xD0..=0xD7) {
            continue;
        }
        if offset + 2 > bytes.len() {
            break;
        }
        let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        if length < 2 || offset + length > bytes.len() {
            break;
        }
        if matches!(
            marker,
            0xC0 | 0xC1
                | 0xC2
                | 0xC3
                | 0xC5
                | 0xC6
                | 0xC7
                | 0xC9
                | 0xCA
                | 0xCB
                | 0xCD
                | 0xCE
                | 0xCF
        ) {
            if length < 8 {
                break;
            }
            let height = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as u32;
            let width = u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]) as u32;
            let components = bytes[offset + 7];
            if width == 0
                || height == 0
                || width > MAX_LOGO_DIMENSION
                || height > MAX_LOGO_DIMENSION
                || !matches!(components, 1 | 3)
            {
                return Err("JPEG: dimensioni o spazio colore non supportati".into());
            }
            return Ok(Logo::Jpeg {
                width,
                height,
                components,
                bytes,
            });
        }
        offset += length;
    }
    Err("header JPEG non valido".into())
}

fn logo_dimensions(logo: &Logo) -> (u32, u32) {
    match logo {
        Logo::RgbPng { width, height, .. } | Logo::Jpeg { width, height, .. } => (*width, *height),
    }
}

fn render_pdf(
    report: &AuditReport,
    theme: &ReportTheme,
    theme_hash: &str,
    logo: Option<&Logo>,
) -> Result<Vec<u8>, String> {
    let text = parse_color(&theme.primary_color)?;
    let secondary = parse_color(&theme.secondary_color)?;
    let accent = parse_color(&theme.accent_color)?;
    let mut pages: Vec<Vec<String>> = Vec::new();
    let mut ops = Vec::new();
    let mut cursor = PAGE_H - 40.0;
    draw_header(
        &mut ops,
        &mut cursor,
        report,
        text,
        secondary,
        accent,
        logo,
        pages.len() + 1,
    );
    draw_summary(&mut ops, &mut cursor, report, text, secondary, accent);
    draw_column_header(&mut ops, &mut cursor, text, accent);

    let disabled = &report.extensions.disabled_requirements;
    let language = baradwatchu_messages::configured_language();
    let mut enabled_rows = Vec::new();
    let mut disabled_rows = Vec::new();
    for result in &report.results {
        if result.status == ResultStatus::Disabled {
            disabled_rows.push(result);
        } else {
            enabled_rows.push(result);
        }
    }
    for result in enabled_rows {
        let extra = report
            .extensions
            .providers
            .iter()
            .filter(|provider| provider.requirement_id == result.id)
            .collect::<Vec<_>>();
        draw_result(
            &mut pages,
            &mut ops,
            &mut cursor,
            result,
            None,
            &extra,
            report,
            text,
            secondary,
            accent,
            logo,
            theme_hash,
        );
    }
    if !disabled_rows.is_empty() || !disabled.is_empty() {
        ensure_space(
            &mut pages,
            &mut ops,
            &mut cursor,
            50.0,
            report,
            text,
            secondary,
            accent,
            logo,
            theme_hash,
        );
        ops.push(text_op(
            MARGIN,
            cursor,
            10.5,
            true,
            text,
            baradwatchu_messages::message("pdf.disabled_heading", language),
        ));
        cursor -= 17.0;
        for result in disabled_rows {
            let meta = disabled.iter().find(|item| item.id == result.id);
            let extra = report
                .extensions
                .providers
                .iter()
                .filter(|provider| provider.requirement_id == result.id)
                .collect::<Vec<_>>();
            draw_result(
                &mut pages,
                &mut ops,
                &mut cursor,
                result,
                meta,
                &extra,
                report,
                text,
                secondary,
                accent,
                logo,
                theme_hash,
            );
        }
    }
    if report.results.is_empty() {
        ops.push(text_op(
            MARGIN,
            cursor,
            9.0,
            false,
            text,
            baradwatchu_messages::message("pdf.empty_report", language),
        ));
    }
    draw_footer(
        &mut ops,
        pages.len() + 1,
        theme_hash,
        accent,
        blend(text, secondary, 0.65),
    );
    pages.push(ops);
    let default_logo = logo.is_none().then(dashboard_brand_logo).transpose()?;
    encode_pdf(pages, logo.or(default_logo.as_ref()))
}

#[allow(clippy::too_many_arguments)] // Renderer state is explicit to keep PDF output deterministic.
fn draw_header(
    ops: &mut Vec<String>,
    cursor: &mut f32,
    report: &AuditReport,
    text: [u8; 3],
    secondary: [u8; 3],
    accent: [u8; 3],
    logo: Option<&Logo>,
    page: usize,
) {
    ops.push(format!(
        "{} rg 0 0 {} {} re f",
        rgb(secondary),
        n(PAGE_W),
        n(PAGE_H)
    ));
    if page == 1 {
        let header_height = logo.map_or(125.0, |image| {
            let (width, height) = logo_dimensions(image);
            let scale = (LOGO_W / width as f32).min(LOGO_H / height as f32);
            (40.0 + height as f32 * scale + 18.0).max(125.0)
        });
        if let Some(logo) = logo {
            let (width, height) = logo_dimensions(logo);
            let scale = (LOGO_W / width as f32).min(LOGO_H / height as f32);
            let fitted_w = width as f32 * scale;
            let fitted_h = height as f32 * scale;
            ops.push(format!(
                "q {} 0 0 {} {} {} cm /Logo Do Q",
                n(fitted_w),
                n(fitted_h),
                n(MARGIN),
                n(PAGE_H - 40.0 - fitted_h)
            ));
        } else {
            // Static snapshot of the original dashboard CSS mark; dashboard remains CSS-rendered.
            ops.push(format!(
                "q 96 0 0 96 {} {} cm /Logo Do Q",
                n(MARGIN - 24.0),
                n(PAGE_H - 124.0)
            ));
            ops.push(brand_wordmark_op(
                MARGIN + 52.0,
                PAGE_H - 78.0,
                text,
                "BaradWatchU",
            ));
            ops.push(text_op(
                MARGIN + 53.0,
                PAGE_H - 93.0,
                7.0,
                true,
                [166, 60, 22],
                baradwatchu_messages::message(
                    "pdf.report_subtitle",
                    baradwatchu_messages::configured_language(),
                ),
            ));
        }
        ops.push(text_op(
            PAGE_W - 145.0,
            PAGE_H - 52.0,
            8.5,
            true,
            text,
            baradwatchu_messages::message(
                "pdf.report_title",
                baradwatchu_messages::configured_language(),
            ),
        ));
        ops.push(text_op(
            PAGE_W - 145.0,
            PAGE_H - 66.0,
            7.5,
            false,
            text,
            &date_utc(report.completed_at_unix_ms),
        ));
        ops.push(format!("{} rg", rgb(accent)));
        ops.push(format!(
            "{} {} 519 1.4 re f",
            n(MARGIN),
            n(PAGE_H - header_height)
        ));
        *cursor = PAGE_H - header_height - 20.0;
    } else {
        ops.push(text_op(
            MARGIN,
            PAGE_H - 36.0,
            10.0,
            true,
            text,
            &format!(
                "BaradWatchU · {}",
                baradwatchu_messages::message(
                    "pdf.report_title",
                    baradwatchu_messages::configured_language(),
                )
            ),
        ));
        ops.push(text_op(
            PAGE_W - 155.0,
            PAGE_H - 36.0,
            8.0,
            false,
            text,
            &date_utc(report.completed_at_unix_ms),
        ));
        ops.push(format!("{} rg", rgb(accent)));
        ops.push(format!("{} {} 519 1 re f", n(MARGIN), n(PAGE_H - 45.0)));
        *cursor = PAGE_H - 63.0;
    }
    let _ = page;
}

fn draw_summary(
    ops: &mut Vec<String>,
    cursor: &mut f32,
    report: &AuditReport,
    text: [u8; 3],
    secondary: [u8; 3],
    accent: [u8; 3],
) {
    let language = baradwatchu_messages::configured_language();
    let counts = count_statuses(&report.results);
    let integrity = count_integrity(&report.results);
    let top = *cursor;
    let muted = blend(text, secondary, 0.65);
    ops.push(text_op(
        MARGIN,
        top,
        8.0,
        true,
        accent,
        baradwatchu_messages::message("pdf.execution_summary", language),
    ));
    ops.push(text_op(
        407.0,
        top,
        7.0,
        true,
        muted,
        baradwatchu_messages::message("pdf.overall_result", language),
    ));
    ops.push(text_op(
        407.0,
        top - 18.0,
        12.0,
        true,
        text,
        &overall(&report.results),
    ));
    ops.push(text_op(
        MARGIN,
        top - 20.0,
        9.0,
        false,
        text,
        &date_utc(report.completed_at_unix_ms),
    ));
    ops.push(text_op(
        MARGIN,
        top - 36.0,
        8.0,
        false,
        muted,
        &format!("BaradWatchU Client {}", report.client.version),
    ));
    for (index, (label, count)) in [
        ("PASS", counts.0),
        ("FAIL", counts.1),
        ("WARNING", counts.2),
        ("ERROR", counts.3),
        (
            baradwatchu_messages::message("pdf.disabled_count", language),
            counts.4,
        ),
    ]
    .iter()
    .enumerate()
    {
        let x = MARGIN + index as f32 * 104.0;
        if index > 0 {
            ops.push(format!(
                "{} RG 0.4 w {} {} m {} {} l S",
                rgb(blend(text, secondary, 0.16)),
                n(x - 12.0),
                n(top - 61.0),
                n(x - 12.0),
                n(top - 91.0)
            ));
        }
        ops.push(text_op(x, top - 75.0, 21.0, true, text, &count.to_string()));
        ops.push(text_op(x, top - 91.0, 7.0, true, muted, label));
    }
    ops.push(text_op(
        MARGIN,
        top - 117.0,
        6.8,
        true,
        accent,
        baradwatchu_messages::message("pdf.application_sha", language),
    ));
    ops.push(mono_op(
        MARGIN,
        top - 130.0,
        7.8,
        text,
        report
            .client
            .sha256
            .as_deref()
            .unwrap_or(baradwatchu_messages::message("pdf.not_available", language)),
    ));
    let mut bottom = top - 147.0;
    let attribution = match &report.initiator {
        Some(req::AuditInitiator::Local) => "LOCAL".to_owned(),
        Some(req::AuditInitiator::Remote {
            operator_display_name,
            server_id,
            server_display_name,
            ..
        }) => format!(
            "REMOTE: {} / {} ({})",
            operator_display_name.as_deref().unwrap_or("?"),
            server_display_name,
            server_id
        ),
        None => baradwatchu_messages::message("pdf.origin_unknown", language).to_owned(),
    };
    for line in wrap(&attribution, 100) {
        ops.push(text_op(MARGIN, bottom, 7.4, false, text, &line));
        bottom -= 11.0;
    }
    if let Some(error) = &report.client.sha256_error {
        for line in wrap(error, 105) {
            ops.push(text_op(MARGIN, bottom, 7.4, false, text, &line));
            bottom -= 11.0;
        }
    }
    ops.push(text_op(
        MARGIN,
        bottom,
        7.6,
        false,
        muted,
        &baradwatchu_messages::message("pdf.tool_integrity", language)
            .replace("{verified}", &integrity.0.to_string())
            .replace("{mismatches}", &integrity.1.to_string())
            .replace("{unknown}", &integrity.2.to_string()),
    ));
    if let Some(installation) = &report.installation {
        bottom -= 11.0;
        let verified = installation.status == crate::requirements::IntegrityStatus::Verified;
        ops.push(text_op(
            MARGIN,
            bottom,
            7.6,
            !verified,
            if verified { muted } else { accent },
            &baradwatchu_messages::message(
                if verified {
                    "pdf.installation_verified"
                } else {
                    "pdf.installation_mismatch"
                },
                language,
            )
            .replace("{verified}", &installation.verified_files.to_string())
            .replace("{files}", &installation.files.len().to_string()),
        ));
    }
    ops.push(format!(
        "{} RG 0.8 w {} {} m 557 {} l S",
        rgb(accent),
        n(MARGIN),
        n(bottom - 15.0),
        n(bottom - 15.0)
    ));
    *cursor = bottom - 37.0;
}

fn draw_column_header(ops: &mut Vec<String>, cursor: &mut f32, text: [u8; 3], accent: [u8; 3]) {
    ops.push(text_op(
        MARGIN,
        *cursor,
        8.0,
        true,
        accent,
        baradwatchu_messages::message(
            "pdf.requirement_origin",
            baradwatchu_messages::configured_language(),
        ),
    ));
    ops.push(text_op(
        250.0,
        *cursor,
        8.0,
        true,
        accent,
        baradwatchu_messages::message(
            "pdf.execution_details",
            baradwatchu_messages::configured_language(),
        ),
    ));
    ops.push(text_op(
        490.0,
        *cursor,
        8.0,
        true,
        accent,
        baradwatchu_messages::message("pdf.result", baradwatchu_messages::configured_language()),
    ));
    *cursor -= 7.0;
    ops.push(format!(
        "{} RG 0.8 w {} {} m 557 {} l S",
        rgb(accent),
        n(MARGIN),
        n(*cursor),
        n(*cursor)
    ));
    *cursor -= 13.0;
    let _ = text;
}

#[allow(clippy::too_many_arguments)] // Row layout needs report, theme, pagination, and column data.
fn draw_result(
    pages: &mut Vec<Vec<String>>,
    ops: &mut Vec<String>,
    cursor: &mut f32,
    result: &ResultRecord,
    disabled: Option<&DisabledRequirement>,
    providers: &[&ProviderResult],
    report: &AuditReport,
    text: [u8; 3],
    secondary: [u8; 3],
    accent: [u8; 3],
    logo: Option<&Logo>,
    theme_hash: &str,
) {
    const LEADING: f32 = 11.5;
    let left = left_lines(result, disabled);
    let middle = middle_lines(result, providers);
    let badges = badge_lines(result);
    let max_lines = left.len().max(middle.len()).max(badges.len() * 2).max(1);
    let full_height = max_lines as f32 * LEADING + 29.0;
    // Keep ordinary requirements together; only exceptionally long rows span pages.
    let requested = if full_height <= PAGE_H - 155.0 {
        full_height
    } else {
        90.0
    };
    ensure_space(
        pages, ops, cursor, requested, report, text, secondary, accent, logo, theme_hash,
    );
    let mut offset = 0;
    while offset < max_lines {
        let continuation = offset > 0;
        let heading_height = if continuation { 22.0 } else { 0.0 };
        ensure_space(
            pages,
            ops,
            cursor,
            65.0 + heading_height,
            report,
            text,
            secondary,
            accent,
            logo,
            theme_hash,
        );
        let top = *cursor;
        let capacity = ((top - 72.0 - heading_height) / LEADING).floor().max(1.0) as usize;
        let count = (max_lines - offset).min(capacity);
        if continuation {
            ops.push(text_op(
                MARGIN,
                top - 10.0,
                8.0,
                true,
                accent,
                &format!("{} · continua", result.id),
            ));
        }
        let body_top = top - heading_height;
        for (x, lines) in [(MARGIN, &left), (250.0, &middle)] {
            for (i, line) in lines.iter().skip(offset).take(count).enumerate() {
                line.draw(
                    ops,
                    x,
                    body_top - 12.0 - i as f32 * LEADING,
                    text,
                    accent,
                    secondary,
                );
            }
        }
        // Place badges on the same pagination grid as the text columns.
        if continuation {
            draw_badge(ops, 490.0, top - 15.0, &badges[0]);
        }
        for (i, badge) in badges.iter().enumerate() {
            let line = i * 2;
            if line >= offset && line < offset + count {
                draw_badge(
                    ops,
                    490.0,
                    body_top - 25.0 - (line - offset) as f32 * LEADING,
                    badge,
                );
            }
        }
        let bottom = body_top - count as f32 * LEADING - 16.0;
        let divider = blend(text, secondary, 0.12);
        for x in [236.0, 479.0] {
            ops.push(format!(
                "{} RG 0.4 w {} {} m {} {} l S",
                rgb(divider),
                n(x),
                n(body_top - 4.0),
                n(x),
                n(bottom + 6.0)
            ));
        }
        ops.push(format!(
            "{} RG 0.5 w {} {} m 557 {} l S",
            rgb(blend(accent, secondary, 0.5)),
            n(MARGIN),
            n(bottom),
            n(bottom)
        ));
        *cursor = bottom - 14.0;
        offset += count;
    }
}

#[allow(clippy::too_many_arguments)] // Page breaks redraw the same report/theme header and footer.
fn ensure_space(
    pages: &mut Vec<Vec<String>>,
    ops: &mut Vec<String>,
    cursor: &mut f32,
    height: f32,
    report: &AuditReport,
    text: [u8; 3],
    secondary: [u8; 3],
    accent: [u8; 3],
    logo: Option<&Logo>,
    theme_hash: &str,
) {
    if *cursor - height >= 50.0 {
        return;
    }
    draw_footer(
        ops,
        pages.len() + 1,
        theme_hash,
        accent,
        blend(text, secondary, 0.65),
    );
    pages.push(std::mem::take(ops));
    draw_header(
        ops,
        cursor,
        report,
        text,
        secondary,
        accent,
        logo,
        pages.len() + 1,
    );
    draw_column_header(ops, cursor, text, accent);
    *cursor -= 8.0;
}

fn draw_footer(
    ops: &mut Vec<String>,
    page: usize,
    theme_hash: &str,
    accent: [u8; 3],
    color: [u8; 3],
) {
    ops.push(format!(
        "{} RG 0.5 w {} 35 m 557 35 l S",
        rgb(accent),
        n(MARGIN)
    ));
    ops.push(text_op(
        MARGIN,
        22.0,
        6.3,
        false,
        color,
        &baradwatchu_messages::message(
            "pdf.footer.template",
            baradwatchu_messages::configured_language(),
        )
        .replace("{version}", TEMPLATE_VERSION)
        .replace("{hash}", theme_hash),
    ));
    ops.push(text_op(525.0, 22.0, 7.0, false, color, &format!("{page}")));
}

#[derive(Clone, Copy)]
enum LineStyle {
    Title,
    Label,
    Body,
    Mono,
    Space,
}
struct ReportLine {
    value: String,
    style: LineStyle,
}
impl ReportLine {
    fn draw(
        &self,
        ops: &mut Vec<String>,
        x: f32,
        y: f32,
        text: [u8; 3],
        accent: [u8; 3],
        background: [u8; 3],
    ) {
        let value = &self.value;
        let operation = match self.style {
            LineStyle::Title => text_op(x, y, 9.0, true, text, value),
            LineStyle::Label => text_op(x, y, 6.8, true, blend(accent, text, 0.75), value),
            LineStyle::Body => text_op(x, y, 8.2, false, text, value),
            LineStyle::Mono => mono_op(x, y, 7.3, blend(text, background, 0.8), value),
            LineStyle::Space => return,
        };
        ops.push(operation);
    }
}
fn add_lines(out: &mut Vec<ReportLine>, value: &str, width: usize, style: LineStyle) {
    let available = if width <= 39 { 190.0 } else { 224.0 };
    for line in wrap(value, width) {
        out.extend(
            wrap_measured(&line, available, style)
                .into_iter()
                .map(|value| ReportLine { value, style }),
        );
    }
}
fn line_text_width(value: &str, style: LineStyle) -> f32 {
    let (size, bold) = match style {
        LineStyle::Title => (9.0, true),
        LineStyle::Label => (6.8, true),
        LineStyle::Body => (8.2, false),
        LineStyle::Mono => return value.chars().count() as f32 * 7.3 * 0.6,
        LineStyle::Space => return 0.0,
    };
    value.chars().map(|ch| font_advance(ch, bold)).sum::<f32>() * size / 1000.0
}
fn wrap_measured(value: &str, available: f32, style: LineStyle) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in value.split_whitespace() {
        let candidate = if line.is_empty() {
            word.to_owned()
        } else {
            format!("{line} {word}")
        };
        if line_text_width(&candidate, style) <= available {
            line = candidate;
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        for ch in word.chars() {
            let candidate = format!("{line}{ch}");
            if line_text_width(&candidate, style) > available && !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            line.push(ch);
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn gap(out: &mut Vec<ReportLine>) {
    if out
        .last()
        .is_some_and(|line| !matches!(line.style, LineStyle::Space))
    {
        out.push(ReportLine {
            value: String::new(),
            style: LineStyle::Space,
        });
    }
}

fn left_lines(result: &ResultRecord, disabled: Option<&DisabledRequirement>) -> Vec<ReportLine> {
    let language = baradwatchu_messages::configured_language();
    let mut out = Vec::new();
    add_lines(&mut out, &result.id, 35, LineStyle::Label);
    add_lines(&mut out, &result.name, 30, LineStyle::Title);
    if !result.description.is_empty() {
        gap(&mut out);
        add_lines(
            &mut out,
            baradwatchu_messages::message("pdf.description", language),
            35,
            LineStyle::Label,
        );
        add_lines(&mut out, &result.description, 39, LineStyle::Body);
    }
    gap(&mut out);
    add_lines(
        &mut out,
        baradwatchu_messages::message("pdf.summary", language),
        35,
        LineStyle::Label,
    );
    add_lines(&mut out, &result.summary, 39, LineStyle::Body);
    gap(&mut out);
    add_lines(
        &mut out,
        &format!(
            "{}  {}",
            baradwatchu_messages::message("pdf.priority", language),
            result.priority
        ),
        38,
        LineStyle::Label,
    );
    if let Some(p) = &result.provenance {
        add_lines(
            &mut out,
            &format!(
                "{}  {}",
                baradwatchu_messages::message("pdf.integrity", language),
                baradwatchu_messages::message(
                    match p.integrity_status {
                        crate::requirements::IntegrityStatus::Verified => "integrity.verified",
                        crate::requirements::IntegrityStatus::Mismatch => "integrity.mismatch",
                        crate::requirements::IntegrityStatus::Unknown => "integrity.unknown",
                    },
                    language
                )
            ),
            38,
            LineStyle::Label,
        );
        gap(&mut out);
        add_lines(
            &mut out,
            baradwatchu_messages::message("pdf.tool_hash", language),
            38,
            LineStyle::Label,
        );
        add_lines(
            &mut out,
            p.actual_sha256
                .as_deref()
                .unwrap_or(baradwatchu_messages::message("pdf.not_available", language)),
            32,
            LineStyle::Mono,
        );
        if p.is_override {
            add_lines(
                &mut out,
                &format!(
                    "{} {}",
                    baradwatchu_messages::message("pdf.replaces", language),
                    p.override_builtin_id.as_deref().unwrap_or("")
                ),
                38,
                LineStyle::Body,
            );
        }
    }
    if let Some(disabled) = disabled {
        gap(&mut out);
        if let Some(reason) = &disabled.reason {
            add_lines(
                &mut out,
                baradwatchu_messages::message("pdf.disabled_reason", language),
                35,
                LineStyle::Label,
            );
            add_lines(&mut out, reason, 39, LineStyle::Body);
        }
        if let Some(author) = &disabled.author {
            add_lines(
                &mut out,
                &baradwatchu_messages::message("pdf.author", language).replace("{value}", author),
                39,
                LineStyle::Body,
            );
        }
        if let Some(at) = disabled.disabled_at_unix_ms {
            add_lines(
                &mut out,
                &baradwatchu_messages::message("pdf.since", language)
                    .replace("{value}", &date_utc(at)),
                39,
                LineStyle::Body,
            );
        }
        if let Some(at) = disabled.expires_at_unix_ms {
            add_lines(
                &mut out,
                &baradwatchu_messages::message("pdf.expires", language)
                    .replace("{value}", &date_utc(at)),
                39,
                LineStyle::Body,
            );
        }
    }
    out
}
fn middle_lines(result: &ResultRecord, providers: &[&ProviderResult]) -> Vec<ReportLine> {
    let language = baradwatchu_messages::configured_language();
    let mut out = Vec::new();
    add_lines(
        &mut out,
        baradwatchu_messages::message("pdf.details", language),
        42,
        LineStyle::Label,
    );
    let mut technical = Vec::new();
    for detail in &result.details {
        if let Some(path) = detail.strip_prefix("Tool eseguito: ") {
            add_lines(
                &mut technical,
                baradwatchu_messages::message("pdf.tool_executed", language),
                42,
                LineStyle::Label,
            );
            add_lines(&mut technical, path, 50, LineStyle::Mono);
        } else if let Some(code) = detail.strip_prefix("Codice uscita tool: ") {
            add_lines(
                &mut technical,
                &baradwatchu_messages::message("pdf.exit_code", language).replace("{value}", code),
                42,
                LineStyle::Label,
            );
        } else {
            let heading = detail
                .split_once(": ")
                .filter(|(label, _)| label.chars().count() < 45);
            if heading.is_none() && detail.contains('=') {
                add_lines(&mut out, detail, 50, LineStyle::Mono);
            } else {
                if out
                    .last()
                    .is_some_and(|line| matches!(line.style, LineStyle::Mono))
                {
                    gap(&mut out);
                }
                if let Some((label, value)) = heading {
                    add_lines(&mut out, label, 42, LineStyle::Title);
                    add_lines(&mut out, value, 48, LineStyle::Body);
                } else {
                    add_lines(&mut out, detail, 48, LineStyle::Body);
                }
                gap(&mut out);
            }
        }
    }

    if out.len() == 1 {
        add_lines(
            &mut out,
            baradwatchu_messages::message(
                "pdf.no_details",
                baradwatchu_messages::configured_language(),
            ),
            48,
            LineStyle::Body,
        );
    }
    for p in providers {
        gap(&mut out);
        add_lines(
            &mut out,
            &format!("PROVIDER  {} · {}", p.provider_id, p.status),
            42,
            LineStyle::Label,
        );
        add_lines(
            &mut out,
            &format!(
                "{} · {}",
                baradwatchu_messages::message(
                    if p.required {
                        "pdf.provider.required"
                    } else {
                        "pdf.provider.optional"
                    },
                    baradwatchu_messages::configured_language(),
                ),
                if p.origin == req::ControlOrigin::Custom {
                    baradwatchu_messages::message(
                        "pdf.provider.custom",
                        baradwatchu_messages::configured_language(),
                    )
                } else {
                    baradwatchu_messages::message(
                        "pdf.provider.builtin",
                        baradwatchu_messages::configured_language(),
                    )
                }
            ),
            48,
            LineStyle::Body,
        );
        add_lines(&mut out, &p.summary, 48, LineStyle::Body);
        for detail in &p.details {
            add_lines(&mut out, detail, 48, LineStyle::Body);
        }
    }
    if !technical.is_empty() {
        gap(&mut out);
        out.extend(technical);
    }
    out
}

fn status_badge(status: ResultStatus) -> (String, [u8; 3], [u8; 3]) {
    let language = baradwatchu_messages::configured_language();
    let (label, background, foreground) = match status {
        ResultStatus::Pass => ("PASS".into(), [37, 112, 76], [255, 255, 255]),
        ResultStatus::Fail => ("FAIL".into(), [174, 42, 43], [255, 255, 255]),
        ResultStatus::Warn => ("WARNING".into(), [245, 190, 70], [35, 28, 10]),
        ResultStatus::Error => ("ERROR".into(), [119, 26, 37], [255, 255, 255]),
        ResultStatus::Disabled => (
            baradwatchu_messages::message("status.disabled", language).to_uppercase(),
            [88, 91, 98],
            [255, 255, 255],
        ),
        ResultStatus::NotApplicable => (
            baradwatchu_messages::message("pdf.badge.not_applicable", language).into(),
            [65, 94, 120],
            [255, 255, 255],
        ),
    };
    (label, background, foreground)
}

/// Badges of the requirement itself: its outcome, then override/custom markers. Provider
/// outcomes are not badges: an unlabeled second PASS/FAIL reads as a duplicate of the
/// requirement's outcome; each provider's status, role and origin are in the details column.
fn badge_lines(result: &ResultRecord) -> Vec<(String, [u8; 3], [u8; 3])> {
    let language = baradwatchu_messages::configured_language();
    let mut out = vec![status_badge(result.status)];
    if let Some(p) = &result.provenance {
        if p.is_override {
            out.push((
                baradwatchu_messages::message("pdf.badge.override", language).to_uppercase(),
                [62, 72, 91],
                [255, 255, 255],
            ));
        }
        if p.origin == crate::requirements::ControlOrigin::Custom {
            out.push((
                baradwatchu_messages::message("pdf.badge.custom", language).to_uppercase(),
                [62, 72, 91],
                [255, 255, 255],
            ));
        }
    }
    out
}

fn font_advance(ch: char, bold: bool) -> f32 {
    // Base-14 Helvetica advances; conservative width for unsupported glyphs.
    const UPPER: [u16; 26] = [
        722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722,
        667, 611, 722, 667, 944, 667, 667, 611,
    ];
    const LOWER: [u16; 26] = [
        556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333,
        500, 278, 556, 500, 722, 500, 500, 500,
    ];
    const LOWER_BOLD: [u16; 26] = [
        556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389,
        556, 333, 611, 556, 778, 556, 556, 500,
    ];
    match ch {
        'A'..='Z' => UPPER[(ch as u8 - b'A') as usize] as f32,
        'a'..='z' => (if bold { LOWER_BOLD } else { LOWER })[(ch as u8 - b'a') as usize] as f32,
        '0'..='9' | '_' => 556.0,
        '/' | ' ' | '.' | ',' | '·' => 278.0,
        '-' | '(' | ')' | ':' | ';' => 333.0,
        _ => 1000.0,
    }
}
fn badge_text_width(label: &str, size: f32) -> f32 {
    label.chars().map(|ch| font_advance(ch, true)).sum::<f32>() * size / 1000.0
}

fn draw_badge(ops: &mut Vec<String>, x: f32, y: f32, badge: &(String, [u8; 3], [u8; 3])) {
    let height = 16.0;
    let size = 6.5;
    let text_width = badge_text_width(&badge.0, size);
    let width = text_width + 14.0;
    // Symmetric soft shadow: every layer has the badge's exact center.
    for (spread, gray) in [(2.8, 0.92), (2.0, 0.84), (1.2, 0.73), (0.5, 0.63)] {
        let shadow = round_rect_path(
            x - spread,
            y - spread,
            width + 2.0 * spread,
            height + 2.0 * spread,
            height / 2.0 + spread,
        );
        ops.push(format!("{gray} {gray} {gray} rg {shadow} f"));
    }
    let pill = round_rect_path(x, y, width, height, height / 2.0);
    ops.push(format!("{} rg {pill} f", rgb(badge.1)));
    ops.push(text_op(x + 7.0, y + 5.7, size, true, badge.2, &badge.0));
}

fn blend(foreground: [u8; 3], background: [u8; 3], amount: f32) -> [u8; 3] {
    std::array::from_fn(|i| {
        (f32::from(foreground[i]) * amount + f32::from(background[i]) * (1.0 - amount)).round()
            as u8
    })
}
fn mono_op(x: f32, y: f32, size: f32, color: [u8; 3], value: &str) -> String {
    format!(
        "{} rg BT /F4 {} Tf 0 Tc 1 0 0 1 {} {} Tm ({}) Tj ET",
        rgb(color),
        n(size),
        n(x),
        n(y),
        pdf_text(value)
    )
}

/// PDF-only static snapshot of the original dashboard CSS, including its offset pupil.
fn dashboard_brand_logo() -> Result<Logo, String> {
    decode_png(include_bytes!("../assets/report-brand-mark.png"))
}

fn round_rect_path(x: f32, y: f32, width: f32, height: f32, radius: f32) -> String {
    let k = radius * 0.552_284_8;
    let mut path = format!(
        "{} {} m {} {} l ",
        n(x + radius),
        n(y),
        n(x + width - radius),
        n(y)
    );
    path.push_str(&format!(
        "{} {} {} {} {} {} c {} {} l ",
        n(x + width - radius + k),
        n(y),
        n(x + width),
        n(y + radius - k),
        n(x + width),
        n(y + radius),
        n(x + width),
        n(y + height - radius),
    ));
    path.push_str(&format!(
        "{} {} {} {} {} {} c {} {} l ",
        n(x + width),
        n(y + height - radius + k),
        n(x + width - radius + k),
        n(y + height),
        n(x + width - radius),
        n(y + height),
        n(x + radius),
        n(y + height),
    ));
    path.push_str(&format!(
        "{} {} {} {} {} {} c {} {} l ",
        n(x + radius - k),
        n(y + height),
        n(x),
        n(y + height - radius + k),
        n(x),
        n(y + height - radius),
        n(x),
        n(y + radius),
    ));
    path.push_str(&format!(
        "{} {} {} {} {} {} c",
        n(x),
        n(y + radius - k),
        n(x + radius - k),
        n(y),
        n(x + radius),
        n(y),
    ));
    path
}

fn brand_wordmark_op(x: f32, y: f32, color: [u8; 3], value: &str) -> String {
    format!(
        "{} rg BT /F3 18 Tf 0.55 Tc 1 0 0 1 {} {} Tm ({}) Tj ET",
        rgb(color),
        n(x),
        n(y),
        pdf_text(value)
    )
}

fn count_statuses(results: &[ResultRecord]) -> (usize, usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0, 0);
    for result in results {
        match result.status {
            ResultStatus::Pass => counts.0 += 1,
            ResultStatus::Fail => counts.1 += 1,
            ResultStatus::Warn => counts.2 += 1,
            ResultStatus::Error => counts.3 += 1,
            ResultStatus::Disabled | ResultStatus::NotApplicable => counts.4 += 1,
        }
    }
    counts
}

fn count_integrity(results: &[ResultRecord]) -> (usize, usize, usize) {
    let mut counts = (0, 0, 0);
    for result in results {
        if let Some(provenance) = &result.provenance {
            match provenance.integrity_status {
                crate::requirements::IntegrityStatus::Verified => counts.0 += 1,
                crate::requirements::IntegrityStatus::Mismatch => counts.1 += 1,
                crate::requirements::IntegrityStatus::Unknown => counts.2 += 1,
            }
        }
    }
    counts
}

fn overall(results: &[ResultRecord]) -> String {
    let language = baradwatchu_messages::configured_language();
    if results.iter().any(|r| r.status == ResultStatus::Error) {
        baradwatchu_messages::message("status.error", language).into()
    } else if results.iter().any(|r| r.status == ResultStatus::Fail) {
        baradwatchu_messages::message("status.fail", language).into()
    } else if results.iter().any(|r| r.status == ResultStatus::Warn) {
        baradwatchu_messages::message("status.warning", language).into()
    } else if results.iter().any(|r| r.status == ResultStatus::Disabled) {
        baradwatchu_messages::message("pdf.overall.exceptions", language).into()
    } else if results.iter().all(|r| r.status == ResultStatus::Pass) {
        baradwatchu_messages::message("status.pass", language).into()
    } else {
        baradwatchu_messages::message("pdf.overall.review", language).into()
    }
}

fn wrap(value: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in value.split_whitespace() {
        if !line.is_empty() && line.chars().count() + word.chars().count() + 1 > width {
            lines.push(std::mem::take(&mut line));
        }
        if word.chars().count() > width {
            let mut chunk = String::new();
            for ch in word.chars() {
                if chunk.chars().count() >= width {
                    lines.push(std::mem::take(&mut chunk));
                }
                chunk.push(ch);
            }
            if !chunk.is_empty() {
                if !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                }
                lines.push(chunk);
            }
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn text_op(x: f32, y: f32, size: f32, bold: bool, color: [u8; 3], value: &str) -> String {
    format!(
        "{} rg BT /{} {} Tf 0 Tc 1 0 0 1 {} {} Tm ({}) Tj ET",
        rgb(color),
        if bold { "F2" } else { "F1" },
        n(size),
        n(x),
        n(y),
        pdf_text(value)
    )
}

fn pdf_text(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        let byte = match ch {
            '\\' => {
                out.push_str("\\\\");
                continue;
            }
            '(' => {
                out.push_str("\\(");
                continue;
            }
            ')' => {
                out.push_str("\\)");
                continue;
            }
            '\n' | '\r' => b' ',
            c if c as u32 <= 0x7F => c as u8,
            '€' => 0x80,
            '‚' => 0x82,
            'ƒ' => 0x83,
            '„' => 0x84,
            '…' => 0x85,
            '†' => 0x86,
            '‡' => 0x87,
            'ˆ' => 0x88,
            '‰' => 0x89,
            'Š' => 0x8A,
            '‹' => 0x8B,
            'Œ' => 0x8C,
            'Ž' => 0x8E,
            '‘' => 0x91,
            '’' => 0x92,
            '“' => 0x93,
            '”' => 0x94,
            '•' => 0x95,
            '–' => 0x96,
            '—' => 0x97,
            '˜' => 0x98,
            '™' => 0x99,
            'š' => 0x9A,
            '›' => 0x9B,
            'œ' => 0x9C,
            'ž' => 0x9E,
            'Ÿ' => 0x9F,
            c if (0xA0..=0xFF).contains(&(c as u32)) => c as u8,
            _ => b'?',
        };
        if (0x20..=0x7E).contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("\\{byte:03o}"));
        }
    }
    out
}

fn rgb(color: [u8; 3]) -> String {
    format!(
        "{:.4} {:.4} {:.4}",
        color[0] as f32 / 255.0,
        color[1] as f32 / 255.0,
        color[2] as f32 / 255.0
    )
}
fn n(value: f32) -> String {
    format!("{value:.2}")
}

fn date_utc(ms: u64) -> String {
    let seconds = ms / 1000;
    let days = (seconds / 86400) as i64;
    let sod = seconds % 86400;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn encode_pdf(mut pages: Vec<Vec<String>>, logo: Option<&Logo>) -> Result<Vec<u8>, String> {
    if pages.is_empty() {
        pages.push(Vec::new());
    }
    let mut objects: Vec<Vec<u8>> = vec![Vec::new(); 7];
    let (logo_obj, alpha_obj, image_stream) = match logo {
        Some(Logo::RgbPng {
            width,
            height,
            rgb,
            alpha,
        }) => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(rgb).map_err(|e| e.to_string())?;
            let rgb = encoder.finish().map_err(|e| e.to_string())?;
            let alpha_bytes = if let Some(alpha) = alpha {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(alpha).map_err(|e| e.to_string())?;
                Some(encoder.finish().map_err(|e| e.to_string())?)
            } else {
                None
            };
            (Some((*width, *height, 3u8)), alpha_bytes, Some(rgb))
        }
        Some(Logo::Jpeg {
            width,
            height,
            components,
            bytes,
        }) => (
            Some((*width, *height, *components)),
            None,
            Some(bytes.clone()),
        ),
        None => (None, None, None),
    };
    let mut next = 7usize;
    let image_id = if logo_obj.is_some() {
        let id = next;
        next += 1;
        Some(id)
    } else {
        None
    };
    let alpha_id = if alpha_obj.is_some() {
        let id = next;
        next += 1;
        Some(id)
    } else {
        None
    };
    let page_ids: Vec<usize> = (0..pages.len())
        .map(|_| {
            let id = next;
            next += 2;
            id
        })
        .collect();
    while objects.len() < next {
        objects.push(Vec::new());
    }
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>".to_vec();
    objects[2] = format!(
        "<< /Type /Pages /Count {} /Kids [{}] >>",
        page_ids.len(),
        page_ids
            .iter()
            .map(|id| format!("{id} 0 R"))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .into_bytes();
    objects[3] =
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_vec();
    objects[4] =
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
            .to_vec();
    objects[5] =
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold /Encoding /WinAnsiEncoding >>"
            .to_vec();
    objects[6] =
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".to_vec();
    if let (Some((width, height, components)), Some(data), Some(id)) =
        (logo_obj, image_stream, image_id)
    {
        let filter = if matches!(logo, Some(Logo::Jpeg { .. })) {
            "/DCTDecode"
        } else {
            "/FlateDecode"
        };
        let color_space = if components == 1 {
            "/DeviceGray"
        } else {
            "/DeviceRGB"
        };
        let smask = alpha_id
            .map(|id| format!(" /SMask {id} 0 R"))
            .unwrap_or_default();
        objects[id] = stream_object(&format!("/Type /XObject /Subtype /Image /Width {width} /Height {height} /ColorSpace {color_space} /BitsPerComponent 8 /Filter {filter}{smask}"), &data);
        if let (Some(alpha), Some(id)) = (alpha_obj, alpha_id) {
            let (w, h, _) = logo_obj.unwrap();
            objects[id] = stream_object(&format!("/Type /XObject /Subtype /Image /Width {w} /Height {h} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode"), &alpha);
        }
    }
    for (page_index, ops) in pages.iter().enumerate() {
        let page_id = page_ids[page_index];
        let content_id = page_id + 1;
        let mut resources = String::from("/Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >>");
        if let Some(id) = image_id {
            resources.push_str(&format!(" /XObject << /Logo {id} 0 R >>"));
        }
        let content = ops.join("\n");
        objects[page_id] = format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << {resources} >> /Contents {content_id} 0 R >>", n(PAGE_W), n(PAGE_H)).into_bytes();
        objects[content_id] = stream_object("", content.as_bytes());
    }
    let mut pdf = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = vec![0usize; objects.len()];
    for id in 1..objects.len() {
        offsets[id] = pdf.len();
        pdf.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        pdf.extend_from_slice(&objects[id]);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len()).as_bytes());
    for offset in offsets.iter().skip(1) {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len()
        )
        .as_bytes(),
    );
    Ok(pdf)
}

fn stream_object(dictionary: &str, data: &[u8]) -> Vec<u8> {
    let mut object = format!("<< {dictionary} /Length {} >>\nstream\n", data.len()).into_bytes();
    object.extend_from_slice(data);
    object.extend_from_slice(b"\nendstream");
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badges_fit_font_advances_and_do_not_inherit_wordmark_tracking() {
        assert!((badge_text_width("WARNING", 6.5) - 31.772).abs() < 0.001);
        for label in [
            "PASS",
            "FAIL",
            "WARNING",
            "ERROR",
            "DISABLED",
            "OVERRIDE",
            "CUSTOM",
            "RICHIESTO",
            "OPZIONALE",
            "N/A",
        ] {
            assert!(badge_text_width(label, 6.5) + 14.0 < 63.0);
            let mut ops = vec![brand_wordmark_op(0.0, 0.0, [0; 3], "BaradWatchU")];
            draw_badge(
                &mut ops,
                490.0,
                200.0,
                &(label.into(), [37, 112, 76], [255; 3]),
            );
            let badge_text = ops.last().unwrap();
            // Tc survives BT/ET in PDF, so every ordinary text run must reset it.
            assert!(badge_text.contains("Tf 0 Tc"));
            assert!(mono_op(0.0, 0.0, 7.3, [0; 3], "hash").contains("Tf 0 Tc"));
        }
    }

    #[test]
    fn only_the_requirement_outcome_is_a_status_badge() {
        // Regression: provider outcomes were drawn as extra unlabeled PASS/FAIL badges,
        // which read as the requirement's outcome shown twice.
        let result = ResultRecord {
            id: "REQ-002".into(),
            name: "Antivirus".into(),
            description: String::new(),
            priority: req::Priority::Highest,
            status: req::ResultStatus::Fail,
            compliance_status: None,
            summary: String::new(),
            details: Vec::new(),
            completed_at_unix_ms: 0,
            provenance: None,
        };
        let badges = badge_lines(&result);
        assert_eq!(badges.len(), 1);
        assert_eq!(badges[0].0, "FAIL");
    }

    #[test]
    fn column_wrapping_keeps_wide_glyphs_inside_the_column() {
        for style in [LineStyle::Title, LineStyle::Body, LineStyle::Mono] {
            let value = "W".repeat(140);
            let lines = wrap_measured(&value, 190.0, style);
            assert_eq!(lines.concat(), value);
            assert!(lines
                .iter()
                .all(|line| line_text_width(line, style) <= 190.0));
        }
    }

    #[test]
    fn tall_custom_logo_reserves_space_above_the_summary() {
        let report: AuditReport = serde_json::from_value(serde_json::json!({
            "schemaVersion": "baradwatchu.audit.v1", "completedAtUnixMs": 1784000000000u64,
            "results": []
        }))
        .unwrap();
        let logo = Logo::RgbPng {
            width: 1,
            height: 10,
            rgb: vec![0; 30],
            alpha: None,
        };
        let mut ops = Vec::new();
        let mut cursor = 0.0;
        draw_header(
            &mut ops,
            &mut cursor,
            &report,
            [17; 3],
            [255; 3],
            [179, 38, 45],
            Some(&logo),
            1,
        );
        assert!(cursor < PAGE_H - 40.0 - LOGO_H - 20.0);
    }

    #[test]
    fn long_requirement_keeps_all_content_across_page_breaks() {
        let mut report: AuditReport = serde_json::from_value(serde_json::json!({
            "schemaVersion": "baradwatchu.audit.v1", "completedAtUnixMs": 1784000000000u64,
            "results": [{ "id": "CUSTOM-LONG", "name": "Long requirement",
                "priority": "HIGH", "status": "WARN", "summary": "Long summary with final-summary-marker",
                "completedAtUnixMs": 1784000000000u64,
                "details": (0..150).map(|i| format!("Evidence-{i:03}: important execution detail")).collect::<Vec<_>>() }]
        })).unwrap();
        report.client.version = "0.0.1".into();
        let bytes = render_pdf(&report, &ReportTheme::default(), &"a".repeat(64), None).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for i in 0..150 {
            assert!(text.contains(&format!("Evidence-{i:03}")));
        }
        assert!(text.contains("final-summary-marker"));
        assert!(text.contains("continua"));
        assert!(text.contains("/BaseFont /Courier"));
        assert!(text.contains("/SMask"));
    }

    #[test]
    fn default_theme_uses_white_black_and_baradwatch_red() {
        let theme = ReportTheme::default();
        assert_eq!(theme.primary_color, "#111111");
        assert_eq!(theme.secondary_color, "#FFFFFF");
        assert_eq!(theme.accent_color, "#B3262D");
        assert!(theme.logo_path.is_none());
    }

    #[test]
    fn theme_rejects_status_color_customization_and_invalid_colors() {
        let theme = ReportTheme {
            primary_color: "red".into(),
            ..ReportTheme::default()
        };
        assert!(validate_theme(&theme).is_err());
        assert!(serde_json::from_str::<ReportTheme>(r##"{"schemaVersion":"baradwatchu.report-theme.v1","logoPath":null,"primaryColor":"#111111","secondaryColor":"#ffffff","accentColor":"#bb0000","passColor":"#ffffff"}"##).is_err());
    }

    #[test]
    fn dashboard_lists_default_theme_and_stores_selection_in_user_configuration() {
        let _env = req::TestEnv::new("pdf-theme");
        // ThemeCatalog is serialize-only: read the API JSON as a value.
        let initial: serde_json::Value =
            serde_json::from_str(&dashboard_theme_json().unwrap()).unwrap();
        assert_eq!(initial["selectedThemeId"], DEFAULT_THEME_ID);
        assert_eq!(initial["themes"].as_array().unwrap().len(), 1);
        assert_eq!(initial["themes"][0]["accentColor"], "#B3262D");
        let themes = themes_dir().unwrap();
        fs::create_dir_all(&themes).unwrap();
        let custom = serde_json::json!({
            "id": "custom-test", "name": "Test theme", "schemaVersion": THEME_SCHEMA,
            "logoPath": null, "primaryColor": "#202020", "secondaryColor": "#FAFAFA", "accentColor": "#B3262D"
        });
        fs::write(themes.join("custom-test.json"), custom.to_string()).unwrap();
        let saved: serde_json::Value =
            serde_json::from_str(&dashboard_update_theme(r#"{"theme":"custom-test"}"#).unwrap())
                .unwrap();
        assert_eq!(saved["selectedThemeId"], "custom-test");
        assert_eq!(selected_theme().unwrap().primary_color, "#202020");
        assert!(theme_path().unwrap().is_file());
    }

    #[test]
    fn transparent_png_logo_is_preserved_with_a_pdf_soft_mask() {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&[210, 20, 30, 0]).unwrap();
        }
        let logo = decode_png(&bytes).unwrap();
        assert!(matches!(logo, Logo::RgbPng { alpha: Some(_), .. }));
        let pdf = encode_pdf(vec![vec!["q Q".into()]], Some(&logo)).unwrap();
        assert!(String::from_utf8_lossy(&pdf).contains("/SMask"));
    }

    #[test]
    fn renderer_emits_valid_pdf_objects_and_summary_data() {
        let report = AuditReport {
            initiator: Some(crate::requirements::AuditInitiator::Local),
            installation: None,
            schema_version: "baradwatchu.audit.v1".into(),
            completed_at_unix_ms: 1_784_000_000_000,
            results: vec![],
            client: req::ClientIdentity {
                version: "0.0.1".into(),
                sha256: Some("abc123".into()),
                sha256_error: None,
            },
            pdf: None,
            extensions: Default::default(),
            log_file: None,
        };
        let bytes = render_pdf(&report, &ReportTheme::default(), &"a".repeat(64), None).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("%PDF-1.7"));
        assert!(text.contains("startxref"));
        assert!(text.contains("BaradWatchU"));
        assert!(text.contains("abc123"));
        assert!(text.contains("RIASSUNTO ESECUZIONE"));
    }
}
