//! Local cryptographic identity (Ed25519) and trust store of BaradWatchU Servers.
//!
//! Milestone 1 rules (see README "Identity and trusted Servers"):
//! - trust never comes from the network: Server public keys are exchanged out of band and
//!   imported from a local file after the operator confirms their fingerprint;
//! - the identity is generated only on an explicit, confirmed request (never at install,
//!   start-up, audit or update time) and is never regenerated implicitly;
//! - the private key never leaves this module: no API, CLI output, log, audit, PDF or
//!   notification carries it;
//! - a trusted Server may only *present* a request; every remote audit still needs the
//!   user's explicit acceptance through the local consent flow (`RemoteRequestCheck` has
//!   no variant that authorizes execution).
//!
//! Storage (`state_home()/identity`, Windows `%LOCALAPPDATA%\baradwatchu\state\identity`):
//! ```text
//! identity/
//! ├── .identity.lock          exclusive lock for every change and for signing
//! ├── state.json              commit pointer {identity: "key-…"|null, trustStore: "trust-…json"|null}
//! ├── key-<16 hex>/           one key pair, never modified after creation
//! │   ├── public.json         public data (key, fingerprint, Device ID)
//! │   └── private.key         Ed25519 seed (owner-only file)
//! └── trust-<16 hex>.json     one trust-store version, never modified after creation
//! ```
//! Every change writes new artifacts, flushes them, then atomically replaces `state.json`
//! (the single commit point) and finally deletes artifacts the pointer no longer names.
//! An interruption therefore leaves either the old or the new state; leftovers are removed
//! by the next change (`recover`). Old private keys are overwritten and deleted on a best
//! effort basis only: SSDs, snapshots and backups may still hold the old bytes.
use crate::events;
use crate::ipc::Principal;
use crate::requirements::{self as req, CliError, CliOutput};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

/// Versioned public format shared with the future Server (export and import).
pub const PUBLIC_IDENTITY_SCHEMA: &str = "baradwatchu.public-identity.v1";
pub const ALGORITHM: &str = "Ed25519";
const STATE_SCHEMA: &str = "baradwatchu.identity-state.v1";
const KEY_RECORD_SCHEMA: &str = "baradwatchu.identity-key.v1";
const PRIVATE_KEY_SCHEMA: &str = "baradwatchu.private-key.v1";
const TRUST_SCHEMA: &str = "baradwatchu.trust-store.v1";
const VIEW_SCHEMA: &str = "baradwatchu.identity-view.v1";
const DIR: &str = "identity";
const LOCK: &str = ".identity.lock";
const STATE_FILE: &str = "state.json";
const PUBLIC_FILE: &str = "public.json";
const PRIVATE_FILE: &str = "private.key";
const DEVICE_ID_DOMAIN: &[u8] = b"baradwatchu.device-id.v1\0";
const SERVER_ID_DOMAIN: &[u8] = b"baradwatchu.server-id.v1\0";
const MAX_IMPORT_BYTES: usize = 64 * 1024;
const MAX_LOCAL_FILE: u64 = 1024 * 1024;
const MAX_SERVERS: usize = 256;
const MAX_NAME: usize = 128;

// ---------------------------------------------------------------------------------------
// Public data model
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

/// `baradwatchu.public-identity.v1`: the only key material that ever leaves the device.
/// `id` and `fingerprint` are derived from `publicKey`; importers recompute and compare them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicIdentity {
    pub schema_version: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub algorithm: String,
    /// Standard padded base64 of the 32-byte Ed25519 public key.
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix_ms: Option<u64>,
    /// SHA-256 of this running Client executable when the public identity is exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustStatus {
    Trusted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedServer {
    pub server_id: String,
    pub name: String,
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub imported_at_unix_ms: u64,
    pub status: TrustStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityStatus {
    NotConfigured,
    Configured,
    Damaged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionState {
    /// Unix: owner-only file and folder, owned by the current user.
    Restricted,
    TooOpen,
    /// Windows/other: a protected per-user ACL is applied at creation but not re-checked.
    NotVerified,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyProtection {
    pub state: ProtectionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustView {
    pub damaged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    pub trusted: usize,
    pub revoked: usize,
    pub servers: Vec<TrustedServer>,
}

/// What CLI and dashboard show. It never contains private key material.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityView {
    pub schema_version: &'static str,
    pub status: IdentityStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<PublicIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection: Option<KeyProtection>,
    pub trust: TrustView,
    pub directory: String,
}

/// A Server public key read from a local file, validated but not yet trusted.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCandidate {
    pub server_id: String,
    pub name: String,
    pub algorithm: &'static str,
    pub public_key: String,
    pub fingerprint: String,
    /// Why the import would be refused (duplicate, revoked, conflict, own key); None = importable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<String>,
}

/// Outcome of checking a request signed by a remote party. No variant authorizes running an
/// audit: a verified trusted Server only earns the right to ask the user (local consent).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteRequestCheck {
    UnknownServer,
    RevokedServer(TrustedServer),
    InvalidSignature,
    RequiresLocalConsent(TrustedServer),
}

// ---------------------------------------------------------------------------------------
// Key encoding, fingerprint and identifiers
// ---------------------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical fingerprint: `SHA256:` + 64 lowercase hex digits of SHA-256 over the 32 raw
/// public key bytes (not over the base64 text).
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    format!("SHA256:{}", hex(&Sha256::digest(public_key)))
}

fn derived_id(prefix: &str, domain: &[u8], public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(public_key);
    let digest = hex(&hasher.finalize()[..8]).to_ascii_uppercase();
    format!(
        "{prefix}-{}-{}-{}-{}",
        &digest[0..4],
        &digest[4..8],
        &digest[8..12],
        &digest[12..16]
    )
}

/// Stable Device ID: `BWU-XXXX-XXXX-XXXX-XXXX`, first 64 bits of SHA-256 over a domain
/// label and the public key. It names the device; trust decisions always use the full key.
pub fn device_id(public_key: &[u8; 32]) -> String {
    derived_id("BWU", DEVICE_ID_DOMAIN, public_key)
}

/// Stable Server ID derived the same way (`SRV-…`); a declared ID must match it.
pub fn server_id(public_key: &[u8; 32]) -> String {
    derived_id("SRV", SERVER_ID_DOMAIN, public_key)
}

pub fn encode_public_key(public_key: &[u8; 32]) -> String {
    BASE64.encode(public_key)
}

/// Parses the canonical base64 text of an Ed25519 public key; rejects other encodings,
/// invalid curve points and weak (small-order) keys.
pub fn parse_public_key(text: &str) -> Result<VerifyingKey, CliError> {
    let invalid = || CliError("Invalid Ed25519 public key".into());
    let bytes = BASE64.decode(text.trim()).map_err(|_| invalid())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| invalid())?;
    if BASE64.encode(bytes) != text.trim() {
        return Err(invalid());
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())?;
    if key.is_weak() {
        return Err(invalid());
    }
    Ok(key)
}

/// Normalizes a fingerprint typed by the operator (`sha256:` prefix optional, any case,
/// spaces or colons between hex groups allowed).
pub fn normalize_fingerprint(text: &str) -> Option<String> {
    let text = text.trim();
    let body = match text.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("sha256:") => &text[7..],
        _ => text,
    };
    let digits: String = body
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    (digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("SHA256:{digits}"))
}

/// Verifies an Ed25519 signature (strict verification, weak keys refused).
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    !key.is_weak()
        && key
            .verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
}

fn clean_name(value: &str) -> Result<String, CliError> {
    let value = value.trim();
    let spoofing = |c: char| {
        c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
    };
    if value.is_empty() || value.chars().count() > MAX_NAME || value.chars().any(spoofing) {
        return Err(CliError(
            "Invalid Server name (1-128 characters, no control characters)".into(),
        ));
    }
    Ok(value.to_owned())
}

// ---------------------------------------------------------------------------------------
// On-disk records
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateFile {
    schema_version: String,
    identity: Option<String>,
    trust_store: Option<String>,
    updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyRecord {
    schema_version: String,
    algorithm: String,
    public_key: String,
    fingerprint: String,
    device_id: String,
    created_at_unix_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateKeyFile {
    schema_version: String,
    algorithm: String,
    /// Standard base64 of the 32-byte Ed25519 secret seed.
    seed: String,
}

impl Drop for PrivateKeyFile {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustStore {
    schema_version: String,
    servers: Vec<TrustedServer>,
}

fn valid_artifact(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .is_some_and(|id| {
            id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn valid_key_name(name: &str) -> bool {
    valid_artifact(name, "key-", "")
}

fn valid_trust_name(name: &str) -> bool {
    valid_artifact(name, "trust-", ".json")
}

// ---------------------------------------------------------------------------------------
// Durable file primitives
// ---------------------------------------------------------------------------------------

pub(crate) fn identity_dir() -> Result<PathBuf, CliError> {
    Ok(req::state_home()?.join(DIR))
}

#[cfg(test)]
thread_local! {
    /// Fault injection: fail right before the commit point (simulated interruption).
    static FAIL_BEFORE_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn sync_dir(dir: &Path) {
    // Unix: make the rename/creation itself durable. Windows has no directory handle sync
    // through std; NTFS journals the metadata change.
    #[cfg(unix)]
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Creates a new file (never overwrites, never follows a link), owner-only on Unix, and
/// flushes it to disk.
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| CliError("Cannot create identity file".into()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| CliError("Cannot write identity file".into()))
}

fn temp_path(dir: &Path) -> Result<PathBuf, CliError> {
    Ok(dir.join(format!(".tmp-{}", crate::consent::random_hex(8)?)))
}

/// Single commit point: write `state.json` through a flushed temporary file and rename it.
fn commit(dir: &Path, state: &StateFile) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|_| CliError("Cannot encode identity state".into()))?;
    let temp = temp_path(dir)?;
    write_new_file(&temp, &bytes)?;
    if fs::rename(&temp, dir.join(STATE_FILE)).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(CliError("Cannot update identity state".into()));
    }
    sync_dir(dir);
    Ok(())
}

thread_local! {
    /// Set only by `load_for_service`: every identity file read on this thread must belong
    /// to this account and be owner-only (checked on the opened handle, not on the path).
    static READ_OWNER: std::cell::RefCell<Option<Principal>> = const { std::cell::RefCell::new(None) };
}

struct OwnerScope;

impl OwnerScope {
    fn enter(owner: &Principal) -> Self {
        READ_OWNER.with(|cell| *cell.borrow_mut() = Some(owner.clone()));
        Self
    }
}

impl Drop for OwnerScope {
    fn drop(&mut self) {
        READ_OWNER.with(|cell| *cell.borrow_mut() = None);
    }
}

fn read_limited(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Identity file is not readable".into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err("Identity file is unsafe".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| "Identity file is not readable".to_owned())?;
    if let Some(owner) = READ_OWNER.with(|cell| cell.borrow().clone()) {
        check_file_owner(&file, &owner)?;
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Identity file is not readable".to_owned())?;
    Ok(Some(bytes))
}

/// The opened file is a regular file owned by `owner` and closed to everybody else.
fn check_file_owner(file: &File, owner: &Principal) -> Result<(), String> {
    let unsafe_file = || "Identity file does not belong to the registered user".to_owned();
    let metadata = file.metadata().map_err(|_| unsafe_file())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(unsafe_file());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if Some(metadata.uid()) != owner.uid() || metadata.mode() & 0o077 != 0 {
            return Err(unsafe_file());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if windows_acl::owner_sid(file).as_deref() != owner.sid() {
            return Err(unsafe_file());
        }
        Ok(())
    }
}

/// Unix: the folder is a real directory owned by `owner` and closed to everybody else.
/// Windows: files are checked one by one (`check_file_owner`).
fn check_dir_owner(dir: &Path, owner: &Principal) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(dir).map_err(|_| "Identity folder is not readable".to_owned())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Identity folder is unsafe".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if Some(metadata.uid()) != owner.uid() || metadata.mode() & 0o077 != 0 {
            return Err("Identity folder does not belong to the registered user".into());
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok(())
}

fn harden_dir(dir: &Path) -> Result<(), CliError> {
    req::secure_dir(dir)?;
    #[cfg(windows)]
    windows_acl::restrict_to_current_user(dir)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) mod windows_acl {
    //! Protected DACL: full control for the current user and SYSTEM only, inherited by
    //! the files below. Administrators can still take ownership (documented limit).
    use crate::requirements::CliError;
    use std::{os::windows::ffi::OsStrExt, path::Path, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL,
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(crate) fn current_user_sid() -> Option<String> {
        // SAFETY: the token handle is closed below; the buffer outlives every SID pointer
        // read from it; the string returned by ConvertSidToStringSidW is freed with LocalFree.
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
            let mut buffer = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) != 0;
            CloseHandle(token);
            if !ok || buffer.len() < std::mem::size_of::<TOKEN_USER>() {
                return None;
            }
            let user = buffer.as_ptr().cast::<TOKEN_USER>().read_unaligned();
            let mut text = ptr::null_mut::<u16>();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 || text.is_null() {
                return None;
            }
            let mut length = 0;
            while *text.add(length) != 0 {
                length += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
            LocalFree(text.cast());
            Some(sid)
        }
    }

    pub(super) fn restrict_to_current_user(path: &Path) -> Result<(), CliError> {
        let sid = current_user_sid()
            .ok_or_else(|| CliError("Cannot restrict identity folder permissions".into()))?;
        restrict(path, &format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"))
    }

    /// Service data folder: SYSTEM and Administrators only.
    pub(crate) fn restrict_to_system(path: &Path) -> Result<(), CliError> {
        restrict(path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    }

    /// Owner SID of an opened file.
    pub(crate) fn owner_sid(file: &std::fs::File) -> Option<String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::{
            Authorization::GetSecurityInfo, OWNER_SECURITY_INFORMATION, PSID,
        };
        // SAFETY: `owner` points into `descriptor`, which is freed after the conversion.
        unsafe {
            let mut owner: PSID = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            if GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            ) != 0
                || owner.is_null()
            {
                return None;
            }
            let mut text = ptr::null_mut::<u16>();
            let converted = ConvertSidToStringSidW(owner, &mut text) != 0 && !text.is_null();
            let sid = converted.then(|| {
                let mut length = 0;
                while *text.add(length) != 0 {
                    length += 1;
                }
                let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
                LocalFree(text.cast());
                sid
            });
            LocalFree(descriptor);
            sid
        }
    }

    fn restrict(path: &Path, sddl: &str) -> Result<(), CliError> {
        let failure = || CliError("Cannot restrict identity folder permissions".into());
        let sddl = wide(sddl);
        let object: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `descriptor` is allocated by the API and freed with LocalFree; `dacl`
        // points into it and is only used before the free.
        unsafe {
            let mut descriptor = ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            ) == 0
            {
                return Err(failure());
            }
            let (mut present, mut defaulted) = (0, 0);
            let mut dacl: *mut ACL = ptr::null_mut();
            let read =
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted);
            let status = if read != 0 && present != 0 {
                SetNamedSecurityInfoW(
                    object.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl,
                    ptr::null(),
                )
            } else {
                1
            };
            LocalFree(descriptor);
            if status != 0 {
                return Err(failure());
            }
        }
        Ok(())
    }
}

fn protection_of(dir: &Path, key_dir: &Path) -> KeyProtection {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        for (path, label) in [
            (dir.to_path_buf(), "identity folder"),
            (key_dir.to_path_buf(), "key folder"),
            (key_dir.join(PRIVATE_FILE), "private key file"),
        ] {
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                return KeyProtection {
                    state: ProtectionState::TooOpen,
                    detail: Some(format!("{label} is missing")),
                };
            };
            if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return KeyProtection {
                    state: ProtectionState::TooOpen,
                    detail: Some(format!(
                        "{label} {:o} (uid {}) is accessible to other users",
                        metadata.mode() & 0o777,
                        metadata.uid()
                    )),
                };
            }
        }
        KeyProtection {
            state: ProtectionState::Restricted,
            detail: None,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, key_dir);
        KeyProtection {
            state: ProtectionState::NotVerified,
            detail: None,
        }
    }
}

/// Best effort: overwrite the private seed before deleting a retired key folder. Not a
/// guarantee of physical erasure (SSD wear levelling, copy-on-write, snapshots, backups).
fn retire_key_dir(path: &Path) {
    let private = path.join(PRIVATE_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&private) {
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            if let Ok(mut file) = OpenOptions::new().write(true).open(&private) {
                let _ = file
                    .write_all(&vec![0u8; metadata.len() as usize])
                    .and_then(|_| file.sync_all());
            }
        }
    }
    let _ = fs::remove_dir_all(path);
}

// ---------------------------------------------------------------------------------------
// Reading the current state (no writes)
// ---------------------------------------------------------------------------------------

fn read_state(dir: &Path) -> Result<Option<StateFile>, String> {
    let Some(bytes) = read_limited(&dir.join(STATE_FILE), MAX_LOCAL_FILE)? else {
        return Ok(None);
    };
    let state: StateFile =
        serde_json::from_slice(&bytes).map_err(|_| "Identity state file is damaged".to_owned())?;
    let names_ok = state.identity.as_deref().map_or(true, valid_key_name)
        && state.trust_store.as_deref().map_or(true, valid_trust_name);
    if state.schema_version != STATE_SCHEMA || !names_ok {
        return Err("Identity state file is damaged".into());
    }
    Ok(Some(state))
}

/// Identity artifacts present on disk (used when `state.json` is missing).
fn has_artifacts(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            valid_key_name(&name) || valid_trust_name(&name)
        })
    })
}

fn read_key_record(dir: &Path, name: &str) -> Result<KeyRecord, String> {
    let bytes = read_limited(&dir.join(name).join(PUBLIC_FILE), MAX_LOCAL_FILE)?
        .ok_or_else(|| "Identity public key file is missing".to_owned())?;
    let record: KeyRecord = serde_json::from_slice(&bytes)
        .map_err(|_| "Identity public key file is damaged".to_owned())?;
    let key = parse_public_key(&record.public_key)
        .map_err(|_| "Identity public key file is damaged".to_owned())?;
    let raw = key.to_bytes();
    if record.schema_version != KEY_RECORD_SCHEMA
        || record.algorithm != ALGORITHM
        || record.fingerprint != fingerprint(&raw)
        || record.device_id != device_id(&raw)
    {
        return Err("Identity public key file is damaged".into());
    }
    Ok(record)
}

/// Loads the private key and checks it matches the public record. Never regenerates.
fn load_signing_key(dir: &Path, name: &str, record: &KeyRecord) -> Result<SigningKey, String> {
    let key_dir = dir.join(name);
    let mut bytes = read_limited(&key_dir.join(PRIVATE_FILE), 4096)?
        .ok_or_else(|| "Identity private key file is missing".to_owned())?;
    let parsed: Result<PrivateKeyFile, _> = serde_json::from_slice(&bytes);
    bytes.zeroize();
    let file = parsed.map_err(|_| "Identity private key file is damaged".to_owned())?;
    if file.schema_version != PRIVATE_KEY_SCHEMA || file.algorithm != ALGORITHM {
        return Err("Identity private key file is damaged".into());
    }
    let mut seed = BASE64
        .decode(file.seed.as_bytes())
        .map_err(|_| "Identity private key file is damaged".to_owned())?;
    let result = <[u8; 32]>::try_from(seed.as_slice())
        .map(|mut array| {
            let key = SigningKey::from_bytes(&array);
            array.zeroize();
            key
        })
        .map_err(|_| "Identity private key file is damaged".to_owned());
    seed.zeroize();
    let key = result?;
    if encode_public_key(&key.verifying_key().to_bytes()) != record.public_key {
        return Err("Identity private and public keys do not match".into());
    }
    Ok(key)
}

fn read_trust(dir: &Path, state: Option<&StateFile>) -> Result<TrustStore, String> {
    let empty = TrustStore {
        schema_version: TRUST_SCHEMA.into(),
        servers: vec![],
    };
    let Some(name) = state.and_then(|state| state.trust_store.as_deref()) else {
        return Ok(empty);
    };
    let bytes = read_limited(&dir.join(name), MAX_LOCAL_FILE)?
        .ok_or_else(|| "Trust store file is missing".to_owned())?;
    let store: TrustStore =
        serde_json::from_slice(&bytes).map_err(|_| "Trust store file is damaged".to_owned())?;
    if store.schema_version != TRUST_SCHEMA || store.servers.len() > MAX_SERVERS {
        return Err("Trust store file is damaged".into());
    }
    for server in &store.servers {
        let key = parse_public_key(&server.public_key)
            .map_err(|_| "Trust store file is damaged".to_owned())?
            .to_bytes();
        if server.fingerprint != fingerprint(&key) || server.server_id != server_id(&key) {
            return Err("Trust store file is damaged".into());
        }
    }
    Ok(store)
}

struct Snapshot {
    status: IdentityStatus,
    identity: Option<(String, KeyRecord)>,
    problem: Option<String>,
    trust: Result<TrustStore, String>,
}

fn snapshot(dir: &Path) -> Snapshot {
    let state = match read_state(dir) {
        Ok(state) => state,
        Err(problem) => {
            return Snapshot {
                status: IdentityStatus::Damaged,
                identity: None,
                problem: Some(problem.clone()),
                trust: Err(problem),
            }
        }
    };
    if state.is_none() && has_artifacts(dir) {
        let problem = "Identity files exist without their state file".to_owned();
        return Snapshot {
            status: IdentityStatus::Damaged,
            identity: None,
            problem: Some(problem.clone()),
            trust: Err(problem),
        };
    }
    let trust = read_trust(dir, state.as_ref());
    let Some(name) = state.as_ref().and_then(|state| state.identity.clone()) else {
        return Snapshot {
            status: IdentityStatus::NotConfigured,
            identity: None,
            problem: None,
            trust,
        };
    };
    let checked = read_key_record(dir, &name)
        .and_then(|record| load_signing_key(dir, &name, &record).map(|_| record));
    match checked {
        Ok(record) => Snapshot {
            status: IdentityStatus::Configured,
            identity: Some((name, record)),
            problem: None,
            trust,
        },
        Err(problem) => Snapshot {
            status: IdentityStatus::Damaged,
            identity: None,
            problem: Some(problem),
            trust,
        },
    }
}

fn local_name() -> Option<String> {
    let raw = if cfg!(windows) {
        std::env::var("COMPUTERNAME").ok()
    } else {
        fs::read_to_string("/etc/hostname")
            .ok()
            .or_else(|| std::env::var("HOSTNAME").ok())
    }?;
    clean_name(raw.lines().next().unwrap_or("")).ok()
}

fn public_identity_of(record: &KeyRecord) -> PublicIdentity {
    let executable_sha256 = std::env::current_exe()
        .ok()
        .and_then(|path| fs::read(path).ok())
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    PublicIdentity {
        schema_version: PUBLIC_IDENTITY_SCHEMA.into(),
        role: Role::Client,
        id: Some(record.device_id.clone()),
        name: local_name(),
        algorithm: ALGORITHM.into(),
        public_key: record.public_key.clone(),
        fingerprint: Some(record.fingerprint.clone()),
        created_at_unix_ms: Some(record.created_at_unix_ms),
        executable_sha256,
    }
}

fn localized(problem: String) -> String {
    baradwatchu_messages::localize_diagnostic(&problem, baradwatchu_messages::configured_language())
}

fn view_at(dir: &Path) -> IdentityView {
    let snapshot = snapshot(dir);
    let protection = snapshot
        .identity
        .as_ref()
        .map(|(name, _)| protection_of(dir, &dir.join(name)));
    let trust = match snapshot.trust {
        Ok(store) => TrustView {
            damaged: false,
            problem: None,
            trusted: store
                .servers
                .iter()
                .filter(|s| s.status == TrustStatus::Trusted)
                .count(),
            revoked: store
                .servers
                .iter()
                .filter(|s| s.status == TrustStatus::Revoked)
                .count(),
            servers: store.servers,
        },
        Err(problem) => TrustView {
            damaged: true,
            problem: Some(localized(problem)),
            trusted: 0,
            revoked: 0,
            servers: vec![],
        },
    };
    IdentityView {
        schema_version: VIEW_SCHEMA,
        status: snapshot.status,
        identity: snapshot
            .identity
            .map(|(_, record)| public_identity_of(&record)),
        problem: snapshot.problem.map(localized),
        protection,
        trust,
        directory: dir.display().to_string(),
    }
}

// ---------------------------------------------------------------------------------------
// Changes (all under the identity lock)
// ---------------------------------------------------------------------------------------

fn locked<T>(task: impl FnOnce(&Path) -> Result<T, CliError>) -> Result<T, CliError> {
    let dir = identity_dir()?;
    let _lock = events::lock_dir(&dir, LOCK)?;
    harden_dir(&dir)?;
    task(&dir)
}

/// Deletes artifacts the committed state no longer references and stale temporary files.
fn collect_garbage(dir: &Path, state: &StateFile) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            if valid_key_name(name) || valid_trust_name(name) || name.starts_with(".tmp-") {
                let _ = fs::remove_file(&path);
            }
            continue;
        }
        if valid_key_name(name) && state.identity.as_deref() != Some(name) && metadata.is_dir() {
            retire_key_dir(&path);
        } else if (valid_trust_name(name) && state.trust_store.as_deref() != Some(name)
            || name.starts_with(".tmp-"))
            && metadata.is_file()
        {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Recovery step run before every change: with a valid committed state, leftovers of an
/// interrupted change are removed. A missing state with leftovers is reported as damaged
/// (never guessed, never regenerated).
fn recover(dir: &Path) -> Result<StateFile, CliError> {
    match read_state(dir) {
        Ok(Some(state)) => {
            collect_garbage(dir, &state);
            Ok(state)
        }
        Ok(None) if has_artifacts(dir) => Err(CliError(
            "Identity data is damaged: use the full reset (identity reset)".into(),
        )),
        Ok(None) => {
            // First change: commit an empty state before creating any artifact, so that an
            // interrupted first generation leaves recoverable leftovers, not a damaged folder.
            let state = StateFile {
                schema_version: STATE_SCHEMA.into(),
                identity: None,
                trust_store: None,
                updated_at_unix_ms: req::now_ms(),
            };
            collect_garbage(dir, &state);
            commit(dir, &state)?;
            Ok(state)
        }
        Err(_) => Err(CliError(
            "Identity data is damaged: use the full reset (identity reset)".into(),
        )),
    }
}

/// Generates a key pair from the OS CSPRNG into a fresh `key-…` folder (not yet committed).
fn create_key_dir(dir: &Path) -> Result<(String, KeyRecord), CliError> {
    let name = format!("key-{}", crate::consent::random_hex(8)?);
    let path = dir.join(&name);
    fs::create_dir(&path).map_err(|_| CliError("Cannot create identity key folder".into()))?;
    let result = (|| {
        req::secure_dir(&path)?;
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|_| CliError("Cannot obtain secure random bytes".into()))?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let public = signing.verifying_key().to_bytes();
        let record = KeyRecord {
            schema_version: KEY_RECORD_SCHEMA.into(),
            algorithm: ALGORITHM.into(),
            public_key: encode_public_key(&public),
            fingerprint: fingerprint(&public),
            device_id: device_id(&public),
            created_at_unix_ms: req::now_ms(),
        };
        let private = PrivateKeyFile {
            schema_version: PRIVATE_KEY_SCHEMA.into(),
            algorithm: ALGORITHM.into(),
            seed: BASE64.encode(signing.to_bytes()),
        };
        let mut text = serde_json::to_vec_pretty(&private)
            .map_err(|_| CliError("Cannot encode identity key".into()))?;
        let written = write_new_file(&path.join(PRIVATE_FILE), &text);
        text.zeroize();
        written?;
        let public_text = serde_json::to_vec_pretty(&record)
            .map_err(|_| CliError("Cannot encode identity key".into()))?;
        write_new_file(&path.join(PUBLIC_FILE), &public_text)?;
        sync_dir(&path);
        sync_dir(dir);
        Ok(record)
    })();
    match result {
        Ok(record) => Ok((name, record)),
        Err(error) => {
            retire_key_dir(&path);
            Err(error)
        }
    }
}

fn write_trust(dir: &Path, store: &TrustStore) -> Result<Option<String>, CliError> {
    if store.servers.is_empty() {
        return Ok(None);
    }
    let name = format!("trust-{}.json", crate::consent::random_hex(8)?);
    let bytes = serde_json::to_vec_pretty(store)
        .map_err(|_| CliError("Cannot encode trust store".into()))?;
    write_new_file(&dir.join(&name), &bytes)?;
    sync_dir(dir);
    Ok(Some(name))
}

fn next_state(previous: &StateFile) -> StateFile {
    StateFile {
        schema_version: STATE_SCHEMA.into(),
        identity: previous.identity.clone(),
        trust_store: previous.trust_store.clone(),
        updated_at_unix_ms: req::now_ms(),
    }
}

/// Commits `state` or, on failure, removes the artifacts created for it.
fn commit_or_discard(dir: &Path, state: &StateFile) -> Result<(), CliError> {
    #[cfg(test)]
    let result = if FAIL_BEFORE_COMMIT.with(|flag| flag.replace(false)) {
        Err(CliError("Simulated interruption".into()))
    } else {
        commit(dir, state)
    };
    #[cfg(not(test))]
    let result = commit(dir, state);
    match result {
        Ok(()) => {
            collect_garbage(dir, state);
            Ok(())
        }
        Err(error) => {
            if let Ok(Some(current)) = read_state(dir) {
                collect_garbage(dir, &current);
            }
            Err(error)
        }
    }
}

/// First generation. Refused when an identity (even a damaged one) already exists.
pub fn generate() -> Result<PublicIdentity, CliError> {
    locked(|dir| {
        let state = recover(dir)?;
        if state.identity.is_some() {
            return Err(CliError(
                "An identity already exists: to replace it use the full reset (identity reset)"
                    .into(),
            ));
        }
        let (name, record) = create_key_dir(dir)?;
        let mut next = next_state(&state);
        next.identity = Some(name);
        commit_or_discard(dir, &next)?;
        Ok(public_identity_of(&record))
    })
}

/// Full reset: new key pair, empty trust store, one atomic commit. Works on a damaged
/// identity too (it is the documented recovery path); refused when none exists.
pub fn reset() -> Result<(PublicIdentity, usize), CliError> {
    let (identity, removed) = locked(|dir| {
        let previous = match read_state(dir) {
            Ok(Some(state)) => {
                collect_garbage(dir, &state);
                Some(state)
            }
            Ok(None) if !has_artifacts(dir) => None,
            _ => Some(StateFile::default()),
        };
        let Some(previous) = previous else {
            return Err(CliError(
                "No identity to reset: generate one with identity generate".into(),
            ));
        };
        let damaged_state = previous.schema_version.is_empty();
        if !damaged_state && previous.identity.is_none() {
            return Err(CliError(
                "No identity to reset: generate one with identity generate".into(),
            ));
        }
        let removed = read_trust(dir, Some(&previous)).map_or(0, |store| store.servers.len());
        let (name, record) = create_key_dir(dir)?;
        let next = StateFile {
            schema_version: STATE_SCHEMA.into(),
            identity: Some(name),
            trust_store: None,
            updated_at_unix_ms: req::now_ms(),
        };
        commit_or_discard(dir, &next)?;
        Ok((public_identity_of(&record), removed))
    })?;
    // Local authorizations tied to the old identity: no pending request may be accepted
    // after the reset (best effort; pending requests also expire on their own).
    let _ = crate::consent::expire_pending();
    Ok((identity, removed))
}

fn parse_server_document(text: &str) -> Result<(PublicIdentity, VerifyingKey), CliError> {
    if text.len() > MAX_IMPORT_BYTES {
        return Err(CliError("Server key file is too large".into()));
    }
    let document: PublicIdentity = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|_| {
            CliError("Server key file is not a valid BaradWatchU public identity".into())
        })?;
    if document.schema_version != PUBLIC_IDENTITY_SCHEMA || document.algorithm != ALGORITHM {
        return Err(CliError(
            "Unsupported public identity format (expected baradwatchu.public-identity.v1, Ed25519)"
                .into(),
        ));
    }
    if document.role != Role::Server {
        return Err(CliError(
            "The file contains a Client identity, not a Server public key".into(),
        ));
    }
    let key = parse_public_key(&document.public_key)?;
    let raw = key.to_bytes();
    if document
        .fingerprint
        .as_deref()
        .is_some_and(|value| normalize_fingerprint(value).as_deref() != Some(&fingerprint(&raw)))
        || document
            .id
            .as_deref()
            .is_some_and(|value| value != server_id(&raw))
    {
        return Err(CliError(
            "Server key file is inconsistent: declared ID or fingerprint does not match the key"
                .into(),
        ));
    }
    Ok((document, key))
}

fn conflict_for(
    store: &TrustStore,
    own_key: Option<&str>,
    candidate: &ServerCandidate,
) -> Option<String> {
    if own_key == Some(candidate.public_key.as_str()) {
        return Some("This is the public key of this Client, not of a Server".into());
    }
    if let Some(existing) = store
        .servers
        .iter()
        .find(|s| s.public_key == candidate.public_key)
    {
        return Some(match existing.status {
            TrustStatus::Trusted => "This Server key is already trusted".into(),
            TrustStatus::Revoked => {
                "This Server key was revoked: it cannot be imported again unless the trust store is cleared"
                    .into()
            }
        });
    }
    if store
        .servers
        .iter()
        .any(|s| s.server_id == candidate.server_id)
    {
        return Some("Server ID conflict with an existing entry".into());
    }
    if store.servers.iter().any(|s| {
        s.status == TrustStatus::Trusted && s.name.to_lowercase() == candidate.name.to_lowercase()
    }) {
        return Some("Another trusted Server already uses this name".into());
    }
    if store.servers.len() >= MAX_SERVERS {
        return Some("Trust store is full".into());
    }
    None
}

fn candidate_from(text: &str) -> Result<ServerCandidate, CliError> {
    let (document, key) = parse_server_document(text)?;
    let raw = key.to_bytes();
    let name = clean_name(document.name.as_deref().unwrap_or(""))?;
    Ok(ServerCandidate {
        server_id: server_id(&raw),
        name,
        algorithm: ALGORITHM,
        public_key: encode_public_key(&raw),
        fingerprint: fingerprint(&raw),
        conflict: None,
    })
}

/// Validates a Server key file and reports what an import would do. Read-only.
pub fn preview_import(text: &str) -> Result<ServerCandidate, CliError> {
    let mut candidate = candidate_from(text)?;
    let dir = identity_dir()?;
    let snapshot = snapshot(&dir);
    let store = snapshot.trust.map_err(|_| {
        CliError("Trust store is damaged: use the full reset (identity reset)".into())
    })?;
    let own = snapshot.identity.map(|(_, record)| record.public_key);
    candidate.conflict = conflict_for(&store, own.as_deref(), &candidate);
    Ok(candidate)
}

/// Imports a Server key as trusted. `confirmed_fingerprint` is the value the operator
/// confirmed after checking it out of band; it must match the key in the file.
pub fn import_server(text: &str, confirmed_fingerprint: &str) -> Result<TrustedServer, CliError> {
    let candidate = candidate_from(text)?;
    if normalize_fingerprint(confirmed_fingerprint).as_deref() != Some(&candidate.fingerprint) {
        return Err(CliError(
            "The confirmed fingerprint does not match the key in the file: nothing imported".into(),
        ));
    }
    locked(|dir| {
        let state = recover(dir)?;
        let mut store = read_trust(dir, Some(&state)).map_err(|_| {
            CliError("Trust store is damaged: use the full reset (identity reset)".into())
        })?;
        let own = state
            .identity
            .as_deref()
            .and_then(|name| read_key_record(dir, name).ok())
            .map(|record| record.public_key);
        if let Some(conflict) = conflict_for(&store, own.as_deref(), &candidate) {
            return Err(CliError(conflict));
        }
        let server = TrustedServer {
            server_id: candidate.server_id.clone(),
            name: candidate.name.clone(),
            algorithm: ALGORITHM.into(),
            public_key: candidate.public_key.clone(),
            fingerprint: candidate.fingerprint.clone(),
            imported_at_unix_ms: req::now_ms(),
            status: TrustStatus::Trusted,
            revoked_at_unix_ms: None,
        };
        store.servers.push(server.clone());
        let mut next = next_state(&state);
        next.trust_store = write_trust(dir, &store)?;
        commit_or_discard(dir, &next)?;
        Ok(server)
    })
}

/// Revokes one Server. The entry is kept (status REVOKED) so the key cannot be re-imported
/// silently; only `clear_servers` forgets revocations.
pub fn revoke_server(id: &str) -> Result<TrustedServer, CliError> {
    let revoked = locked(|dir| {
        let state = recover(dir)?;
        let mut store = read_trust(dir, Some(&state)).map_err(|_| {
            CliError("Trust store is damaged: use the full reset (identity reset)".into())
        })?;
        let server = store
            .servers
            .iter_mut()
            .find(|s| s.server_id.eq_ignore_ascii_case(id.trim()))
            .ok_or_else(|| CliError("Server not found in the trust store".into()))?;
        if server.status == TrustStatus::Revoked {
            return Err(CliError("Server already revoked".into()));
        }
        server.status = TrustStatus::Revoked;
        server.revoked_at_unix_ms = Some(req::now_ms());
        let revoked = server.clone();
        let mut next = next_state(&state);
        next.trust_store = write_trust(dir, &store)?;
        commit_or_discard(dir, &next)?;
        Ok(revoked)
    })?;
    // Milestone 2: a pending request of this Server can no longer be accepted.
    let _ = crate::consent::expire_remote_pending(Some(&revoked.server_id));
    Ok(revoked)
}

/// «Remove all trusted Servers»: forgets every Server (trusted and revoked); the Client
/// identity, Device ID and fingerprint stay unchanged. A damaged trust store can be
/// cleared too. Returns how many entries were removed.
pub fn clear_servers() -> Result<usize, CliError> {
    let removed = locked(|dir| {
        let state = recover(dir)?;
        let removed = read_trust(dir, Some(&state)).map_or(0, |store| store.servers.len());
        if state.trust_store.is_none() {
            return Ok(0);
        }
        let mut next = next_state(&state);
        next.trust_store = None;
        commit_or_discard(dir, &next)?;
        Ok(removed)
    })?;
    let _ = crate::consent::expire_remote_pending(None);
    Ok(removed)
}

/// Milestone 2: what the system service needs from one registered user's identity to
/// terminate mutual TLS on that user's behalf. Read-only; never written back.
pub(crate) struct ServiceIdentity {
    pub device_id: String,
    pub signing_key: SigningKey,
    /// Trusted and revoked entries; use `trusted`.
    pub servers: Vec<TrustedServer>,
}

impl ServiceIdentity {
    /// The trusted, non-revoked Server owning exactly this key.
    pub fn trusted(&self, public_key: &[u8; 32]) -> Option<&TrustedServer> {
        let encoded = encode_public_key(public_key);
        self.servers
            .iter()
            .find(|s| s.public_key == encoded && s.status == TrustStatus::Trusted)
    }
}

/// Loads the identity a user registered with the service. Every folder and file must be
/// owned by that user and closed to others (checked on opened handles, links refused),
/// so the service can never be pointed at somebody else's key. No lock is taken (the
/// service must not create files in the user's folder): artifacts are immutable and
/// `state.json` is replaced atomically, so one retry covers a concurrent change.
pub(crate) fn load_for_service(dir: &Path, owner: &Principal) -> Result<ServiceIdentity, String> {
    load_for_service_once(dir, owner).or_else(|_| load_for_service_once(dir, owner))
}

fn load_for_service_once(dir: &Path, owner: &Principal) -> Result<ServiceIdentity, String> {
    if !dir.is_absolute() {
        return Err("Identity folder must be an absolute path".into());
    }
    check_dir_owner(dir, owner)?;
    let _scope = OwnerScope::enter(owner);
    let state = read_state(dir)?.ok_or_else(|| "No local identity".to_owned())?;
    let name = state
        .identity
        .clone()
        .ok_or_else(|| "No local identity".to_owned())?;
    check_dir_owner(&dir.join(&name), owner)?;
    let record = read_key_record(dir, &name)?;
    let signing_key = load_signing_key(dir, &name, &record)?;
    let trust = read_trust(dir, Some(&state))?;
    Ok(ServiceIdentity {
        device_id: record.device_id,
        signing_key,
        servers: trust.servers,
    })
}

// ---------------------------------------------------------------------------------------
// Interfaces for later milestones
// ---------------------------------------------------------------------------------------

pub fn view() -> Result<IdentityView, CliError> {
    Ok(view_at(&identity_dir()?))
}

/// The local public identity, if configured and intact.
pub fn public_identity() -> Result<Option<PublicIdentity>, CliError> {
    let dir = identity_dir()?;
    Ok(snapshot(&dir)
        .identity
        .map(|(_, record)| public_identity_of(&record)))
}

/// Signs `message` with the local private key. Refused when the identity is missing,
/// damaged or its files are accessible to other users (Unix).
pub fn sign(message: &[u8]) -> Result<[u8; 64], CliError> {
    if fs::symlink_metadata(identity_dir()?.join(STATE_FILE)).is_err() {
        return Err(CliError(
            "No local identity: generate one with identity generate".into(),
        ));
    }
    locked(|dir| {
        let state = read_state(dir).map_err(|_| {
            CliError("Identity data is damaged: use the full reset (identity reset)".into())
        })?;
        let name = state.and_then(|state| state.identity).ok_or_else(|| {
            CliError("No local identity: generate one with identity generate".into())
        })?;
        let damaged =
            |_| CliError("Identity data is damaged: use the full reset (identity reset)".into());
        let record = read_key_record(dir, &name).map_err(damaged)?;
        if protection_of(dir, &dir.join(&name)).state == ProtectionState::TooOpen {
            return Err(CliError(
                "Identity key files are accessible to other users: signing refused".into(),
            ));
        }
        let key = load_signing_key(dir, &name, &record).map_err(damaged)?;
        Ok(key.sign(message).to_bytes())
    })
}

/// The trusted, non-revoked Server that owns exactly this public key (never matched by
/// name, address or declared ID).
pub fn trusted_server_for_key(public_key: &[u8; 32]) -> Result<Option<TrustedServer>, CliError> {
    let encoded = encode_public_key(public_key);
    let dir = identity_dir()?;
    let store = snapshot(&dir).trust.map_err(|_| {
        CliError("Trust store is damaged: use the full reset (identity reset)".into())
    })?;
    Ok(store
        .servers
        .into_iter()
        .find(|s| s.public_key == encoded && s.status == TrustStatus::Trusted))
}

/// Contract for future remote requests: the presented key must be in the trust store and
/// not revoked, and the signature must verify with that key. Even then the result is only
/// `RequiresLocalConsent`: the user must accept through the notification flow.
pub fn check_remote_request(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<RemoteRequestCheck, CliError> {
    let encoded = encode_public_key(public_key);
    let dir = identity_dir()?;
    let store = snapshot(&dir).trust.map_err(|_| {
        CliError("Trust store is damaged: use the full reset (identity reset)".into())
    })?;
    let Some(server) = store.servers.into_iter().find(|s| s.public_key == encoded) else {
        return Ok(RemoteRequestCheck::UnknownServer);
    };
    if server.status == TrustStatus::Revoked {
        return Ok(RemoteRequestCheck::RevokedServer(server));
    }
    if !verify_signature(public_key, message, signature) {
        return Ok(RemoteRequestCheck::InvalidSignature);
    }
    Ok(RemoteRequestCheck::RequiresLocalConsent(server))
}

// ---------------------------------------------------------------------------------------
// Dashboard API (loopback bridge; token, Host, Origin and Content-Type checked by dashboard.rs)
// ---------------------------------------------------------------------------------------

fn view_json() -> Result<String, CliError> {
    req::output_json(&view()?)
}

pub(crate) fn dashboard_view_json() -> Result<String, CliError> {
    view_json()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfirmBody {
    confirm: bool,
}

fn require_confirmation(text: &str) -> Result<(), CliError> {
    match serde_json::from_str::<ConfirmBody>(text) {
        Ok(ConfirmBody { confirm: true }) => Ok(()),
        _ => Err(CliError(
            "Explicit confirmation required: nothing was changed".into(),
        )),
    }
}

pub(crate) fn dashboard_generate(text: &str) -> Result<String, CliError> {
    require_confirmation(text)?;
    generate()?;
    view_json()
}

pub(crate) fn dashboard_reset(text: &str) -> Result<String, CliError> {
    require_confirmation(text)?;
    reset()?;
    view_json()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportBody {
    content: String,
    #[serde(default)]
    confirm_fingerprint: Option<String>,
}

pub(crate) fn dashboard_trust_preview(text: &str) -> Result<String, CliError> {
    let body: ImportBody =
        serde_json::from_str(text).map_err(|_| CliError("Invalid trust import request".into()))?;
    let mut candidate = preview_import(&body.content)?;
    candidate.conflict = candidate.conflict.map(localized);
    req::output_json(&candidate)
}

pub(crate) fn dashboard_trust_import(text: &str) -> Result<String, CliError> {
    let body: ImportBody =
        serde_json::from_str(text).map_err(|_| CliError("Invalid trust import request".into()))?;
    let confirmed = body
        .confirm_fingerprint
        .ok_or_else(|| CliError("Explicit confirmation required: nothing was changed".into()))?;
    import_server(&body.content, &confirmed)?;
    view_json()
}

pub(crate) fn dashboard_trust_revoke(id: &str, text: &str) -> Result<String, CliError> {
    require_confirmation(text)?;
    revoke_server(id)?;
    view_json()
}

pub(crate) fn dashboard_trust_clear(text: &str) -> Result<String, CliError> {
    require_confirmation(text)?;
    clear_servers()?;
    view_json()
}

// ---------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------

/// Interactive confirmation source (terminal in production, scripted in tests).
pub(crate) trait Prompter {
    fn interactive(&self) -> bool;
    /// Shows `text` on stderr and returns the typed line (None on EOF/error).
    fn ask(&mut self, text: &str) -> Option<String>;
}

struct Terminal;

impl Prompter for Terminal {
    fn interactive(&self) -> bool {
        io::stdin().is_terminal()
    }
    fn ask(&mut self, text: &str) -> Option<String> {
        let mut stderr = io::stderr().lock();
        let _ = write!(stderr, "{text}");
        let _ = stderr.flush();
        let mut line = String::new();
        match io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line),
        }
    }
}

fn msg(key: &str) -> String {
    baradwatchu_messages::message(key, baradwatchu_messages::configured_language()).to_owned()
}

fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "s" | "si" | "sì" | "y" | "yes"
    )
}

enum Confirmation {
    Confirmed,
    Cancelled,
}

/// `warning` is always shown. `--yes` confirms non-interactively; without it a terminal is
/// required. `strong` asks the user to type RESET instead of yes.
fn confirm(
    prompter: &mut dyn Prompter,
    warning: &str,
    assume_yes: bool,
    strong: bool,
) -> Result<Confirmation, CliError> {
    if assume_yes {
        eprint!("{warning}");
        return Ok(Confirmation::Confirmed);
    }
    if !prompter.interactive() {
        eprint!("{warning}");
        return Err(CliError(
            "Confirmation required: run the command in a terminal or add --yes".into(),
        ));
    }
    let prompt = msg(if strong {
        "identity.reset.prompt"
    } else {
        "identity.confirm.prompt"
    });
    let answer = prompter.ask(&format!("{warning}\n{prompt}"));
    let accepted = answer.is_some_and(|answer| {
        if strong {
            answer.trim() == "RESET"
        } else {
            is_yes(&answer)
        }
    });
    Ok(if accepted {
        Confirmation::Confirmed
    } else {
        Confirmation::Cancelled
    })
}

fn cancelled() -> CliOutput {
    CliOutput {
        text: msg("identity.cancelled"),
        code: 1,
    }
}

fn format_time(ms: u64) -> String {
    let seconds = ms / 1000;
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm), UTC.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn protection_text(protection: &KeyProtection) -> String {
    let label = msg(match protection.state {
        ProtectionState::Restricted => "identity.protection.restricted",
        ProtectionState::TooOpen => "identity.protection.too_open",
        ProtectionState::NotVerified => "identity.protection.not_verified",
    });
    match &protection.detail {
        Some(detail) => format!("{label} ({detail})"),
        None => label,
    }
}

fn identity_text(view: &IdentityView) -> String {
    match (view.status, &view.identity) {
        (IdentityStatus::Configured, Some(identity)) => msg("identity.show.block")
            .replace("{device}", identity.id.as_deref().unwrap_or(""))
            .replace(
                "{fingerprint}",
                identity.fingerprint.as_deref().unwrap_or(""),
            )
            .replace("{key}", &identity.public_key)
            .replace(
                "{created}",
                &identity
                    .created_at_unix_ms
                    .map(format_time)
                    .unwrap_or_default(),
            )
            .replace(
                "{protection}",
                &view
                    .protection
                    .as_ref()
                    .map(protection_text)
                    .unwrap_or_default(),
            )
            .replace("{servers}", &view.trust.trusted.to_string())
            .replace("{directory}", &view.directory),
        (IdentityStatus::Damaged, _) => msg("identity.show.damaged")
            .replace(
                "{problem}",
                &baradwatchu_messages::localize_diagnostic(
                    view.problem.as_deref().unwrap_or(""),
                    baradwatchu_messages::configured_language(),
                ),
            )
            .replace("{directory}", &view.directory),
        _ => msg("identity.show.none"),
    }
}

fn server_text(server: &TrustedServer) -> String {
    msg("trust.show.block")
        .replace("{id}", &server.server_id)
        .replace("{name}", &server.name)
        .replace(
            "{status}",
            &msg(match server.status {
                TrustStatus::Trusted => "trust.status.trusted",
                TrustStatus::Revoked => "trust.status.revoked",
            }),
        )
        .replace("{fingerprint}", &server.fingerprint)
        .replace("{key}", &server.public_key)
        .replace("{imported}", &format_time(server.imported_at_unix_ms))
        .replace(
            "{revoked}",
            &server
                .revoked_at_unix_ms
                .map(|ms| msg("trust.show.revoked_at").replace("{date}", &format_time(ms)))
                .unwrap_or_default(),
        )
}

fn text_arg(value: &OsString, usage: &str) -> Result<String, CliError> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| CliError(usage.into()))
}

fn identity_usage() -> String {
    msg("identity.usage")
}

fn trust_usage() -> String {
    msg("trust.usage")
}

pub fn run_identity(args: &[OsString]) -> Result<CliOutput, CliError> {
    run_identity_with(args, &mut Terminal)
}

pub fn run_trust(args: &[OsString]) -> Result<CliOutput, CliError> {
    run_trust_with(args, &mut Terminal)
}

fn flags(options: &[OsString], allowed: &[&str], usage: &str) -> Result<Vec<String>, CliError> {
    let mut seen = Vec::new();
    for option in options {
        let option = text_arg(option, usage)?;
        if !allowed.contains(&option.as_str()) || seen.contains(&option) {
            return Err(CliError(usage.into()));
        }
        seen.push(option);
    }
    Ok(seen)
}

pub(crate) fn run_identity_with(
    args: &[OsString],
    prompter: &mut dyn Prompter,
) -> Result<CliOutput, CliError> {
    let usage = identity_usage();
    let Some((command, options)) = args.split_first() else {
        return Err(CliError(usage));
    };
    let ok = |text: String| Ok(CliOutput { text, code: 0 });
    match text_arg(command, &usage)?.as_str() {
        "--help" | "-h" | "help" if options.is_empty() => ok(msg("identity.help")),
        "generate" => {
            let yes = flags(options, &["--yes"], &usage)?.contains(&"--yes".to_owned());
            // Refuse before asking when an identity already exists.
            let current = view()?;
            if current.status != IdentityStatus::NotConfigured {
                return Err(CliError(
                    "An identity already exists: to replace it use the full reset (identity reset)"
                        .into(),
                ));
            }
            match confirm(prompter, &msg("identity.generate.warning"), yes, false)? {
                Confirmation::Cancelled => Ok(cancelled()),
                Confirmation::Confirmed => {
                    generate()?;
                    ok(msg("identity.generated") + &identity_text(&view()?))
                }
            }
        }
        "show" => {
            let json = flags(options, &["--json"], &usage)?.contains(&"--json".to_owned());
            let view = view()?;
            if json {
                ok(req::output_json(&view)?)
            } else {
                ok(identity_text(&view))
            }
        }
        "export" => {
            let identity = public_identity()?.ok_or_else(|| {
                CliError("No local identity: generate one with identity generate".into())
            })?;
            if identity.executable_sha256.is_none() {
                return Err(CliError(
                    "Cannot read the current Client executable to compute its SHA-256".into(),
                ));
            }
            let text = req::output_json(&identity)?;
            match options {
                [] => ok(text),
                [flag, path] if flag == "--output" => {
                    let path = PathBuf::from(path);
                    write_new_file(&path, text.as_bytes()).map_err(|_| {
                        CliError("Cannot write the export file (it must not exist yet)".into())
                    })?;
                    ok(msg("identity.export.saved").replace("{path}", &path.display().to_string()))
                }
                _ => Err(CliError(usage)),
            }
        }
        "reset" => {
            let yes = flags(options, &["--yes"], &usage)?.contains(&"--yes".to_owned());
            if view()?.status == IdentityStatus::NotConfigured {
                return Err(CliError(
                    "No identity to reset: generate one with identity generate".into(),
                ));
            }
            match confirm(prompter, &msg("identity.reset.warning"), yes, true)? {
                Confirmation::Cancelled => Ok(cancelled()),
                Confirmation::Confirmed => {
                    let (_, removed) = reset()?;
                    ok(
                        msg("identity.reset.done").replace("{servers}", &removed.to_string())
                            + &identity_text(&view()?),
                    )
                }
            }
        }
        _ => Err(CliError(usage)),
    }
}

pub(crate) fn run_trust_with(
    args: &[OsString],
    prompter: &mut dyn Prompter,
) -> Result<CliOutput, CliError> {
    let usage = trust_usage();
    let Some((command, options)) = args.split_first() else {
        return Err(CliError(usage));
    };
    let ok = |text: String| Ok(CliOutput { text, code: 0 });
    let store = || -> Result<TrustView, CliError> {
        let view = view()?;
        if view.trust.damaged {
            return Err(CliError(
                "Trust store is damaged: use the full reset (identity reset)".into(),
            ));
        }
        Ok(view.trust)
    };
    match text_arg(command, &usage)?.as_str() {
        "--help" | "-h" | "help" if options.is_empty() => ok(msg("trust.help")),
        "list" => {
            let json = flags(options, &["--json"], &usage)?.contains(&"--json".to_owned());
            let trust = store()?;
            if json {
                return ok(req::output_json(&trust.servers)?);
            }
            if trust.servers.is_empty() {
                return ok(msg("trust.list.none"));
            }
            ok(trust
                .servers
                .iter()
                .map(|server| {
                    msg("trust.list.row")
                        .replace("{id}", &server.server_id)
                        .replace(
                            "{status}",
                            &msg(match server.status {
                                TrustStatus::Trusted => "trust.status.trusted",
                                TrustStatus::Revoked => "trust.status.revoked",
                            }),
                        )
                        .replace("{name}", &server.name)
                        .replace("{fingerprint}", &server.fingerprint)
                })
                .collect())
        }
        "show" => {
            let (id, json) = match options {
                [id] => (text_arg(id, &usage)?, false),
                [id, flag] if flag == "--json" => (text_arg(id, &usage)?, true),
                _ => return Err(CliError(usage)),
            };
            let server = store()?
                .servers
                .into_iter()
                .find(|s| s.server_id.eq_ignore_ascii_case(id.trim()))
                .ok_or_else(|| CliError("Server not found in the trust store".into()))?;
            if json {
                ok(req::output_json(&server)?)
            } else {
                ok(server_text(&server))
            }
        }
        "import" => {
            let Some((file, rest)) = options.split_first() else {
                return Err(CliError(usage));
            };
            let expected = match rest {
                [] => None,
                [flag, value] if flag == "--fingerprint" => Some(text_arg(value, &usage)?),
                _ => return Err(CliError(usage)),
            };
            let path = PathBuf::from(file);
            let bytes = read_limited(&path, MAX_IMPORT_BYTES as u64)
                .map_err(|_| CliError("Cannot read the Server key file".into()))?
                .ok_or_else(|| CliError("Cannot read the Server key file".into()))?;
            let text = String::from_utf8(bytes).map_err(|_| {
                CliError("Server key file is not a valid BaradWatchU public identity".into())
            })?;
            let candidate = preview_import(&text)?;
            let preview = msg("trust.import.preview")
                .replace("{name}", &candidate.name)
                .replace("{id}", &candidate.server_id)
                .replace("{fingerprint}", &candidate.fingerprint);
            if let Some(conflict) = &candidate.conflict {
                eprint!("{preview}");
                return Err(CliError(conflict.clone()));
            }
            let confirmed = match expected {
                Some(expected) => {
                    eprint!("{preview}");
                    expected
                }
                None => {
                    if !prompter.interactive() {
                        eprint!("{preview}");
                        return Err(CliError(
                            "Confirmation required: run in a terminal or pass --fingerprint with the verified value"
                                .into(),
                        ));
                    }
                    let answer = prompter
                        .ask(&format!("{preview}\n{}", msg("trust.import.prompt")))
                        .unwrap_or_default();
                    if !is_yes(&answer) {
                        return Ok(cancelled());
                    }
                    candidate.fingerprint.clone()
                }
            };
            let server = import_server(&text, &confirmed)?;
            ok(msg("trust.import.done")
                .replace("{name}", &server.name)
                .replace("{id}", &server.server_id))
        }
        "revoke" => {
            let Some((id, rest)) = options.split_first() else {
                return Err(CliError(usage));
            };
            let id = text_arg(id, &usage)?;
            let yes = flags(rest, &["--yes"], &usage)?.contains(&"--yes".to_owned());
            let server = store()?
                .servers
                .into_iter()
                .find(|s| s.server_id.eq_ignore_ascii_case(id.trim()))
                .ok_or_else(|| CliError("Server not found in the trust store".into()))?;
            if server.status == TrustStatus::Revoked {
                return Err(CliError("Server already revoked".into()));
            }
            let warning = msg("trust.revoke.warning")
                .replace("{name}", &server.name)
                .replace("{id}", &server.server_id);
            match confirm(prompter, &warning, yes, false)? {
                Confirmation::Cancelled => Ok(cancelled()),
                Confirmation::Confirmed => {
                    let revoked = revoke_server(&server.server_id)?;
                    ok(msg("trust.revoke.done")
                        .replace("{name}", &revoked.name)
                        .replace("{id}", &revoked.server_id))
                }
            }
        }
        "clear" => {
            let yes = flags(options, &["--yes"], &usage)?.contains(&"--yes".to_owned());
            let count = view()?.trust.servers.len();
            let warning = msg("trust.clear.warning").replace("{count}", &count.to_string());
            match confirm(prompter, &warning, yes, false)? {
                Confirmation::Cancelled => Ok(cancelled()),
                Confirmation::Confirmed => {
                    let removed = clear_servers()?;
                    ok(msg("trust.clear.done").replace("{count}", &removed.to_string()))
                }
            }
        }
        _ => Err(CliError(usage)),
    }
}

// ---------------------------------------------------------------------------------------
// Tests (isolated XDG folders through TestEnv; never the operator's real keys)
// ---------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requirements::TestEnv;

    struct Scripted {
        interactive: bool,
        answers: Vec<&'static str>,
        asked: Vec<String>,
    }

    impl Scripted {
        fn new(interactive: bool, answers: &[&'static str]) -> Self {
            Self {
                interactive,
                answers: answers.iter().rev().copied().collect(),
                asked: vec![],
            }
        }
    }

    impl Prompter for Scripted {
        fn interactive(&self) -> bool {
            self.interactive
        }
        fn ask(&mut self, text: &str) -> Option<String> {
            self.asked.push(text.to_owned());
            self.answers.pop().map(|answer| format!("{answer}\n"))
        }
    }

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn dir() -> PathBuf {
        identity_dir().unwrap()
    }

    /// Server key file as the future Server would export it.
    fn server_file(name: &str, seed: u8) -> (String, [u8; 32], SigningKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let public = signing.verifying_key().to_bytes();
        let document = PublicIdentity {
            schema_version: PUBLIC_IDENTITY_SCHEMA.into(),
            role: Role::Server,
            id: Some(server_id(&public)),
            name: Some(name.into()),
            algorithm: ALGORITHM.into(),
            public_key: encode_public_key(&public),
            fingerprint: Some(fingerprint(&public)),
            created_at_unix_ms: None,
            executable_sha256: None,
        };
        (serde_json::to_string(&document).unwrap(), public, signing)
    }

    fn import(text: &str) -> Result<TrustedServer, CliError> {
        let candidate = candidate_from(text)?;
        import_server(text, &candidate.fingerprint)
    }

    fn private_seed() -> String {
        let state = read_state(&dir()).unwrap().unwrap();
        let bytes = fs::read(dir().join(state.identity.unwrap()).join(PRIVATE_FILE)).unwrap();
        let file: PrivateKeyFile = serde_json::from_slice(&bytes).unwrap();
        file.seed.clone()
    }

    fn tree(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = vec![];
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(tree(&path));
                } else {
                    out.push((path.clone(), fs::read(&path).unwrap_or_default()));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn identity_is_absent_until_explicitly_generated() {
        let _env = TestEnv::new("identity-absent");
        let view = view().unwrap();
        assert_eq!(view.status, IdentityStatus::NotConfigured);
        assert!(view.identity.is_none());
        assert!(public_identity().unwrap().is_none());
        // Reading never creates anything.
        assert!(!dir().exists());
        assert!(sign(b"x").is_err());
        let output = run_identity_with(&args(&["show"]), &mut Scripted::new(true, &[])).unwrap();
        assert_eq!(output.code, 0);
        assert!(!dir().join(STATE_FILE).exists());
    }

    #[test]
    fn generation_requires_confirmation_and_cancel_changes_nothing() {
        let _env = TestEnv::new("identity-cancel");
        // Non-interactive without --yes: refused, warning shown, no state.
        let error =
            run_identity_with(&args(&["generate"]), &mut Scripted::new(false, &[])).unwrap_err();
        assert!(error.0.contains("Confirmation required"));
        assert!(!dir().exists());
        // Interactive "no": cancelled, exit 1, nothing written.
        let mut prompter = Scripted::new(true, &["no"]);
        let output = run_identity_with(&args(&["generate"]), &mut prompter).unwrap();
        assert_eq!(output.code, 1);
        assert!(prompter.asked[0].contains("BaradWatchU Server"));
        assert!(!dir().exists());
        // Interactive "sì": generated.
        let output =
            run_identity_with(&args(&["generate"]), &mut Scripted::new(true, &["sì"])).unwrap();
        assert_eq!(output.code, 0);
        assert_eq!(view().unwrap().status, IdentityStatus::Configured);
        // A second generation is refused and points to the reset.
        let error = run_identity_with(&args(&["generate", "--yes"]), &mut Scripted::new(true, &[]))
            .unwrap_err();
        assert!(error.0.contains("identity reset"));
        assert!(generate().is_err());
    }

    #[test]
    fn identity_persists_and_device_id_is_stable() {
        let _env = TestEnv::new("identity-persist");
        let created = generate().unwrap();
        let public = parse_public_key(&created.public_key).unwrap().to_bytes();
        assert_eq!(created.id.as_deref(), Some(device_id(&public).as_str()));
        assert_eq!(
            created.fingerprint.as_deref(),
            Some(fingerprint(&public).as_str())
        );
        assert!(created.id.as_ref().unwrap().starts_with("BWU-"));
        assert_eq!(created.id.as_ref().unwrap().len(), 23);
        // "Restart": everything is read back from disk.
        for _ in 0..3 {
            let again = public_identity().unwrap().unwrap();
            assert_eq!(again.public_key, created.public_key);
            assert_eq!(again.id, created.id);
        }
        // Fingerprint/ID derivation is deterministic and documented.
        let key = [7u8; 32];
        assert_eq!(
            fingerprint(&key),
            format!("SHA256:{}", hex(&Sha256::digest(key)))
        );
        assert_eq!(device_id(&key), device_id(&key));
        assert_ne!(device_id(&key), server_id(&key)[..].replace("SRV", "BWU"));
        #[cfg(unix)]
        assert_eq!(
            view().unwrap().protection.unwrap().state,
            ProtectionState::Restricted
        );
    }

    #[cfg(unix)]
    #[test]
    fn service_reads_only_owner_only_identities_of_the_registered_account() {
        use std::os::unix::fs::PermissionsExt;
        let _env = TestEnv::new("identity-service");
        let dir = identity_dir().unwrap();
        let me = Principal::current().unwrap();
        assert!(load_for_service(&dir, &me).is_err(), "no identity yet");
        let identity = generate().unwrap();
        let loaded = load_for_service(&dir, &me).unwrap();
        assert_eq!(Some(loaded.device_id.clone()), identity.id);
        assert_eq!(
            encode_public_key(&loaded.signing_key.verifying_key().to_bytes()),
            identity.public_key
        );
        // Another account, a relative path or loosened permissions: refused.
        assert!(load_for_service(&dir, &Principal("uid:4242424".into())).is_err());
        assert!(load_for_service(Path::new("relative/identity"), &me).is_err());
        let name = read_state(&dir).unwrap().unwrap().identity.unwrap();
        let private = dir.join(&name).join(PRIVATE_FILE);
        fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_for_service(&dir, &me).is_err());
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
        // A link in place of the folder is never followed.
        let link = dir.with_file_name("identity-link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(load_for_service(&link, &me).is_err());
        // Trust is read fresh: a revoked Server is no longer trusted.
        let server = SigningKey::from_bytes(&[5; 32]);
        let key = server.verifying_key().to_bytes();
        let document = format!(
            r#"{{"schemaVersion":"{PUBLIC_IDENTITY_SCHEMA}","role":"server","name":"S","algorithm":"Ed25519","publicKey":"{}"}}"#,
            encode_public_key(&key)
        );
        let imported = import_server(&document, &fingerprint(&key)).unwrap();
        assert!(load_for_service(&dir, &me).unwrap().trusted(&key).is_some());
        revoke_server(&imported.server_id).unwrap();
        assert!(load_for_service(&dir, &me).unwrap().trusted(&key).is_none());
    }

    #[test]
    fn sign_and_verify() {
        let _env = TestEnv::new("identity-sign");
        let identity = generate().unwrap();
        let public = parse_public_key(&identity.public_key).unwrap().to_bytes();
        let signature = sign(b"audit request").unwrap();
        assert!(verify_signature(&public, b"audit request", &signature));
        assert!(!verify_signature(&public, b"audit request!", &signature));
        let mut forged = signature;
        forged[0] ^= 1;
        assert!(!verify_signature(&public, b"audit request", &forged));
        assert!(!verify_signature(&[0u8; 32], b"audit request", &signature));
    }

    #[test]
    fn export_contains_only_public_data_and_no_output_leaks_the_private_key() {
        let _env = TestEnv::new("identity-export");
        let mut prompter = Scripted::new(true, &["y"]);
        let generated = run_identity_with(&args(&["generate"]), &mut prompter).unwrap();
        let seed = private_seed();
        let export = run_identity_with(&args(&["export"]), &mut prompter).unwrap();
        let document: PublicIdentity = serde_json::from_str(&export.text).unwrap();
        assert_eq!(document.schema_version, PUBLIC_IDENTITY_SCHEMA);
        assert_eq!(document.role, Role::Client);
        assert!(parse_public_key(&document.public_key).is_ok());
        let show = run_identity_with(&args(&["show"]), &mut prompter).unwrap();
        let show_json = run_identity_with(&args(&["show", "--json"]), &mut prompter).unwrap();
        let api = dashboard_view_json().unwrap();
        for text in [
            &generated.text,
            &export.text,
            &show.text,
            &show_json.text,
            &api,
        ] {
            assert!(!text.contains(&seed), "private seed leaked");
            assert!(!text.to_lowercase().contains("seed"));
            assert!(!text.contains(PRIVATE_KEY_SCHEMA));
        }
        // Public key is shown in full (never truncated).
        assert!(show.text.contains(&document.public_key));
        assert!(api.contains(&document.public_key));
        // --output never overwrites.
        let target = _env.root.join("export.json");
        run_identity_with(
            &args(&["export", "--output", target.to_str().unwrap()]),
            &mut prompter,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), export.text);
        assert!(run_identity_with(
            &args(&["export", "--output", target.to_str().unwrap()]),
            &mut prompter
        )
        .is_err());
    }

    #[test]
    fn importing_a_server_requires_a_matching_fingerprint() {
        let _env = TestEnv::new("trust-import");
        let (text, public, _) = server_file("Server Roma", 1);
        let preview = preview_import(&text).unwrap();
        assert_eq!(preview.fingerprint, fingerprint(&public));
        assert!(preview.conflict.is_none());
        assert!(!dir().exists(), "preview must not write");
        // Wrong confirmation: nothing imported.
        let (other, _, _) = server_file("Altro", 2);
        let wrong = candidate_from(&other).unwrap().fingerprint;
        assert!(import_server(&text, &wrong).is_err());
        assert!(view().unwrap().trust.servers.is_empty());
        // Formatted confirmation is normalized.
        let typed = preview
            .fingerprint
            .to_uppercase()
            .replacen("SHA256:", "sha256: ", 1);
        let server = import_server(&text, &typed).unwrap();
        assert_eq!(server.status, TrustStatus::Trusted);
        assert_eq!(server.server_id, server_id(&public));
        assert_eq!(
            trusted_server_for_key(&public).unwrap().unwrap().name,
            "Server Roma"
        );
        // Trust store works without a local identity (independent).
        assert_eq!(view().unwrap().status, IdentityStatus::NotConfigured);
    }

    #[test]
    fn malformed_duplicate_and_conflicting_keys_are_refused() {
        let _env = TestEnv::new("trust-refuse");
        let (text, public, _) = server_file("Server Roma", 1);
        for bad in [
            "",
            "not json",
            r#"{"schemaVersion":"baradwatchu.public-identity.v1","role":"server","name":"X","algorithm":"Ed25519","publicKey":"AAAA"}"#,
            &text.replace("\"server\"", "\"client\""),
            &text.replace("Ed25519", "RSA"),
            &text.replace("public-identity.v1", "public-identity.v9"),
            &text.replace("Server Roma", "Bad\u{202e}Name"),
            &text.replacen("\"name\":\"Server Roma\",", "", 1),
            &text.replace(&server_id(&public), "SRV-0000-0000-0000-0000"),
            &text.replacen("SHA256:", "SHA256:0", 1),
            &format!("{}{}", text.trim_end_matches('}'), ",\"extra\":1}"),
        ] {
            assert!(preview_import(bad).is_err(), "accepted: {bad}");
        }
        // Weak (small-order) key.
        let weak = text.replace(&encode_public_key(&public), &encode_public_key(&[0u8; 32]));
        assert!(candidate_from(&weak).is_err());
        assert!(candidate_from(&"x".repeat(MAX_IMPORT_BYTES + 1)).is_err());

        import(&text).unwrap();
        assert!(import(&text).unwrap_err().0.contains("already trusted"));
        assert!(preview_import(&text).unwrap().conflict.is_some());
        // Same name, other key: conflict.
        let (same_name, _, _) = server_file("server roma", 3);
        assert!(import(&same_name).unwrap_err().0.contains("name"));
        // Own Client key presented as a Server: refused.
        let own = generate().unwrap();
        let own_file = text
            .replace(&encode_public_key(&public), &own.public_key)
            .replacen(
                &server_id(&public),
                &server_id(&parse_public_key(&own.public_key).unwrap().to_bytes()),
                1,
            )
            .replacen(
                &fingerprint(&public),
                own.fingerprint.as_deref().unwrap(),
                1,
            )
            .replace("Server Roma", "Me");
        assert!(import(&own_file).unwrap_err().0.contains("this Client"));
        assert_eq!(view().unwrap().trust.servers.len(), 1);
    }

    #[test]
    fn revoke_keeps_the_record_and_blocks_reimport() {
        let _env = TestEnv::new("trust-revoke");
        let (text, public, signing) = server_file("Server Roma", 1);
        let server = import(&text).unwrap();
        let (other, other_public, _) = server_file("Server Milano", 2);
        import(&other).unwrap();
        let message = b"request";
        let signature = signing.sign(message).to_bytes();
        assert!(matches!(
            check_remote_request(&public, message, &signature).unwrap(),
            RemoteRequestCheck::RequiresLocalConsent(_)
        ));
        assert_eq!(
            check_remote_request(&public, b"tampered", &signature).unwrap(),
            RemoteRequestCheck::InvalidSignature
        );
        // A trusted Server's name or ID is not proof: a signature by another key fails.
        let impostor = SigningKey::from_bytes(&[9u8; 32]).sign(message).to_bytes();
        assert_eq!(
            check_remote_request(&public, message, &impostor).unwrap(),
            RemoteRequestCheck::InvalidSignature
        );
        let unknown = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            check_remote_request(&unknown, message, &impostor).unwrap(),
            RemoteRequestCheck::UnknownServer
        );

        let mut prompter = Scripted::new(true, &["no"]);
        let output = run_trust_with(&args(&["revoke", &server.server_id]), &mut prompter).unwrap();
        assert_eq!(output.code, 1);
        assert_eq!(view().unwrap().trust.revoked, 0);
        run_trust_with(
            &args(&["revoke", &server.server_id, "--yes"]),
            &mut prompter,
        )
        .unwrap();
        let trust = view().unwrap().trust;
        assert_eq!((trust.trusted, trust.revoked), (1, 1));
        assert!(trusted_server_for_key(&public).unwrap().is_none());
        assert!(trusted_server_for_key(&other_public).unwrap().is_some());
        assert!(matches!(
            check_remote_request(&public, message, &signature).unwrap(),
            RemoteRequestCheck::RevokedServer(_)
        ));
        assert!(revoke_server(&server.server_id)
            .unwrap_err()
            .0
            .contains("already"));
        assert!(import(&text).unwrap_err().0.contains("revoked"));
        assert!(revoke_server("SRV-0000-0000-0000-0000").is_err());
    }

    #[test]
    fn clearing_servers_keeps_the_identity() {
        let _env = TestEnv::new("trust-clear");
        let identity = generate().unwrap();
        let seed = private_seed();
        import(&server_file("A", 1).0).unwrap();
        let revoked = import(&server_file("B", 2).0).unwrap();
        revoke_server(&revoked.server_id).unwrap();
        // Cancel: nothing changes.
        let output = run_trust_with(&args(&["clear"]), &mut Scripted::new(true, &["n"])).unwrap();
        assert_eq!(output.code, 1);
        assert_eq!(view().unwrap().trust.servers.len(), 2);
        assert!(run_trust_with(&args(&["clear"]), &mut Scripted::new(false, &[])).is_err());
        let output = run_trust_with(&args(&["clear"]), &mut Scripted::new(true, &["sì"])).unwrap();
        assert_eq!(output.code, 0);
        let view = view().unwrap();
        assert!(view.trust.servers.is_empty());
        assert_eq!(view.identity.unwrap(), identity);
        assert_eq!(private_seed(), seed);
        // Revocations are forgotten only by this explicit clear: the key imports again.
        import(&server_file("B", 2).0).unwrap();
        // Exactly one trust file and one key folder remain on disk.
        let names: Vec<_> = fs::read_dir(dir())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        assert_eq!(names.len(), 3, "{names:?}");
    }

    #[test]
    fn reset_replaces_identity_and_empties_trust_store() {
        let _env = TestEnv::new("identity-reset");
        let mut prompter = Scripted::new(true, &[]);
        assert!(run_identity_with(&args(&["reset", "--yes"]), &mut prompter)
            .unwrap_err()
            .0
            .contains("identity generate"));
        let old = generate().unwrap();
        let old_seed = private_seed();
        let old_state = read_state(&dir()).unwrap().unwrap();
        import(&server_file("A", 1).0).unwrap();
        let pending =
            crate::consent::create_simulated(crate::consent::SimulationParams::default()).unwrap();

        // Cancel ("yes" is not enough: RESET must be typed), then non-interactive refusal.
        let before = tree(&dir());
        let mut prompter = Scripted::new(true, &["yes"]);
        let output = run_identity_with(&args(&["reset"]), &mut prompter).unwrap();
        assert_eq!(output.code, 1);
        assert!(prompter.asked[0].contains("RESET"));
        assert!(run_identity_with(&args(&["reset"]), &mut Scripted::new(false, &[])).is_err());
        assert_eq!(tree(&dir()), before, "cancelled reset changed files");

        let output =
            run_identity_with(&args(&["reset"]), &mut Scripted::new(true, &["RESET"])).unwrap();
        assert_eq!(output.code, 0);
        let view = view().unwrap();
        let new = view.identity.unwrap();
        assert_ne!(new.public_key, old.public_key);
        assert_ne!(new.id, old.id);
        assert_ne!(private_seed(), old_seed);
        assert!(view.trust.servers.is_empty());
        assert!(!dir().join(old_state.identity.unwrap()).exists());
        // Pending local consent requests no longer accept a decision.
        assert!(crate::consent::decide(
            &pending.request.request_id,
            true,
            crate::consent::DecisionChannel::Cli
        )
        .is_err());
    }

    #[test]
    fn interrupted_generation_and_reset_leave_a_coherent_state() {
        let _env = TestEnv::new("identity-interrupt");
        FAIL_BEFORE_COMMIT.with(|flag| flag.set(true));
        assert!(generate().is_err());
        assert_eq!(view().unwrap().status, IdentityStatus::NotConfigured);
        // A leftover key folder from a crash before the commit is never adopted ...
        let (orphan, _) = create_key_dir(&dir()).unwrap();
        assert_eq!(view().unwrap().status, IdentityStatus::NotConfigured);
        // ... and is removed by the next change.
        let identity = generate().unwrap();
        assert!(!dir().join(&orphan).exists());

        import(&server_file("A", 1).0).unwrap();
        FAIL_BEFORE_COMMIT.with(|flag| flag.set(true));
        assert!(reset().is_err());
        let view = view().unwrap();
        assert_eq!(
            view.identity.unwrap(),
            identity,
            "old identity must survive"
        );
        assert_eq!(view.trust.servers.len(), 1, "old trust must survive");
        let entries = fs::read_dir(dir()).unwrap().count();
        assert_eq!(entries, 4, "lock, state, one key folder, one trust file");
    }

    #[test]
    fn damaged_or_missing_files_are_reported_never_regenerated() {
        let _env = TestEnv::new("identity-damaged");
        let identity = generate().unwrap();
        let state = read_state(&dir()).unwrap().unwrap();
        let key_dir = dir().join(state.identity.as_ref().unwrap());

        // Corrupted private key.
        let private = key_dir.join(PRIVATE_FILE);
        let saved = fs::read(&private).unwrap();
        fs::write(&private, b"{garbage").unwrap();
        let view_damaged = view().unwrap();
        assert_eq!(view_damaged.status, IdentityStatus::Damaged);
        assert!(sign(b"x").is_err());
        assert!(generate().unwrap_err().0.contains("identity reset"));
        fs::write(&private, &saved).unwrap();
        assert_eq!(view().unwrap().status, IdentityStatus::Configured);

        // Missing private key.
        fs::rename(&private, key_dir.join("moved")).unwrap();
        assert_eq!(view().unwrap().status, IdentityStatus::Damaged);
        fs::rename(key_dir.join("moved"), &private).unwrap();

        // Public file not matching the private key.
        let other = SigningKey::from_bytes(&[5u8; 32])
            .verifying_key()
            .to_bytes();
        let public_path = key_dir.join(PUBLIC_FILE);
        let public_saved = fs::read_to_string(&public_path).unwrap();
        let mut record: KeyRecord = serde_json::from_str(&public_saved).unwrap();
        record.public_key = encode_public_key(&other);
        record.fingerprint = fingerprint(&other);
        record.device_id = device_id(&other);
        fs::write(&public_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(view().unwrap().status, IdentityStatus::Damaged);
        fs::write(&public_path, public_saved).unwrap();

        // Missing state file with key material on disk: damaged, nothing deleted or adopted.
        fs::rename(dir().join(STATE_FILE), dir().join("state.bak")).unwrap();
        assert_eq!(view().unwrap().status, IdentityStatus::Damaged);
        assert!(generate().is_err());
        assert!(key_dir.exists());
        fs::rename(dir().join("state.bak"), dir().join(STATE_FILE)).unwrap();

        // Corrupted state file; the reset is the recovery path.
        fs::write(dir().join(STATE_FILE), b"[]").unwrap();
        assert_eq!(view().unwrap().status, IdentityStatus::Damaged);
        assert!(import(&server_file("A", 1).0).is_err());
        let (fresh, _) = reset().unwrap();
        assert_ne!(fresh.public_key, identity.public_key);
        assert_eq!(view().unwrap().status, IdentityStatus::Configured);
        assert!(!key_dir.exists());

        // Corrupted trust store.
        import(&server_file("A", 1).0).unwrap();
        let state = read_state(&dir()).unwrap().unwrap();
        fs::write(dir().join(state.trust_store.unwrap()), b"{").unwrap();
        let view = view().unwrap();
        assert!(view.trust.damaged);
        assert_eq!(view.status, IdentityStatus::Configured);
        assert!(run_trust_with(&args(&["list"]), &mut Scripted::new(true, &[])).is_err());
        assert_eq!(clear_servers().unwrap(), 0);
        assert!(!super::view().unwrap().trust.damaged);
    }

    #[cfg(unix)]
    #[test]
    fn permissions_are_owner_only_and_checked() {
        use std::os::unix::fs::PermissionsExt;
        let mut env = TestEnv::new("identity-perms");
        generate().unwrap();
        let state = read_state(&dir()).unwrap().unwrap();
        let key_dir = dir().join(state.identity.unwrap());
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir()), 0o700);
        assert_eq!(mode(&key_dir), 0o700);
        assert_eq!(mode(&key_dir.join(PRIVATE_FILE)), 0o600);
        assert_eq!(mode(&key_dir.join(PUBLIC_FILE)), 0o600);
        fs::set_permissions(
            key_dir.join(PRIVATE_FILE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(
            view().unwrap().protection.unwrap().state,
            ProtectionState::TooOpen
        );
        assert!(sign(b"x").unwrap_err().0.contains("other users"));
        fs::set_permissions(
            key_dir.join(PRIVATE_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(sign(b"x").is_ok());

        // Read errors: an unreadable private key is reported, never replaced.
        fs::set_permissions(
            key_dir.join(PRIVATE_FILE),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        if fs::read(key_dir.join(PRIVATE_FILE)).is_err() {
            assert_eq!(view().unwrap().status, IdentityStatus::Damaged);
            assert!(generate().is_err());
        }
        fs::set_permissions(
            key_dir.join(PRIVATE_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(view().unwrap().status, IdentityStatus::Configured);

        // Unreadable import file.
        let file = env.root.join("server.json");
        fs::write(&file, server_file("A", 1).0).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&file).is_err() {
            assert!(run_trust_with(
                &args(&["import", file.to_str().unwrap()]),
                &mut Scripted::new(true, &["sì"])
            )
            .is_err());
        }
        // A symlink is refused as an import source.
        let link = env.root.join("link.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(run_trust_with(
            &args(&["import", link.to_str().unwrap()]),
            &mut Scripted::new(true, &["sì"])
        )
        .is_err());

        // Write errors: a regular file where the identity folder should be makes every
        // change fail cleanly (works as root too, unlike permission bits).
        let blocked = env.root.join("blocked");
        fs::create_dir_all(blocked.join("baradwatchu")).unwrap();
        fs::write(blocked.join("baradwatchu/identity"), b"not a folder").unwrap();
        env.set("XDG_STATE_HOME", &blocked);
        assert!(generate().is_err());
        assert!(import(&server_file("A", 1).0).is_err());
        assert!(sign(b"x").is_err());
        assert_eq!(view().unwrap().status, IdentityStatus::Damaged);
    }

    #[test]
    fn concurrent_generation_creates_exactly_one_identity() {
        let _env = TestEnv::new("identity-concurrent");
        let results: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(generate))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let created: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(created.len(), 1);
        let identity = public_identity().unwrap().unwrap();
        assert_eq!(&identity, created[0]);
        let keys = fs::read_dir(dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| valid_key_name(&e.file_name().to_string_lossy()))
            .count();
        assert_eq!(keys, 1);

        // Concurrent resets and imports: the final state is always coherent.
        let handles: Vec<_> = (0..6)
            .map(|i| {
                std::thread::spawn(move || {
                    if i % 2 == 0 {
                        reset().map(|_| ())
                    } else {
                        import(&server_file(&format!("S{i}"), i as u8 + 10).0).map(|_| ())
                    }
                })
            })
            .collect();
        for handle in handles {
            let _ = handle.join().unwrap();
        }
        let view = view().unwrap();
        assert_eq!(view.status, IdentityStatus::Configured);
        assert!(!view.trust.damaged);
        let keys = fs::read_dir(dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| valid_key_name(&e.file_name().to_string_lossy()))
            .count();
        assert_eq!(keys, 1);
    }

    #[test]
    fn cli_import_shows_preview_and_needs_confirmation() {
        let env = TestEnv::new("trust-cli");
        let (text, public, _) = server_file("Server Roma", 1);
        let file = env.root.join("server.json");
        fs::write(&file, &text).unwrap();
        let path = file.to_str().unwrap();
        // Non-interactive without --fingerprint: refused.
        assert!(run_trust_with(&args(&["import", path]), &mut Scripted::new(false, &[])).is_err());
        // Cancelled.
        let mut prompter = Scripted::new(true, &["no"]);
        assert_eq!(
            run_trust_with(&args(&["import", path]), &mut prompter)
                .unwrap()
                .code,
            1
        );
        assert!(prompter.asked[0].contains(&fingerprint(&public)));
        assert!(prompter.asked[0].contains("Server Roma"));
        assert!(view().unwrap().trust.servers.is_empty());
        // Wrong verified fingerprint: refused.
        assert!(run_trust_with(
            &args(&["import", path, "--fingerprint", &fingerprint(&[1u8; 32])]),
            &mut Scripted::new(false, &[])
        )
        .is_err());
        // Correct verified fingerprint: imported without a prompt.
        let output = run_trust_with(
            &args(&["import", path, "--fingerprint", &fingerprint(&public)]),
            &mut Scripted::new(false, &[]),
        )
        .unwrap();
        assert_eq!(output.code, 0);
        let id = server_id(&public);
        let list = run_trust_with(&args(&["list"]), &mut prompter).unwrap();
        assert!(list.text.contains(&id));
        let show = run_trust_with(&args(&["show", &id.to_lowercase()]), &mut prompter).unwrap();
        assert!(show.text.contains(&encode_public_key(&public)));
        let json = run_trust_with(&args(&["list", "--json"]), &mut prompter).unwrap();
        let servers: Vec<TrustedServer> = serde_json::from_str(&json.text).unwrap();
        assert_eq!(servers.len(), 1);
        for bad in [
            &["import"][..],
            &["show"],
            &["revoke"],
            &["clear", "--force"],
            &["list", "--json", "--json"],
            &["nope"],
        ] {
            assert!(
                run_trust_with(&args(bad), &mut prompter).is_err(),
                "{bad:?}"
            );
        }
        for bad in [
            &["generate", "--force"][..],
            &["export", "--output"],
            &["nope"],
            &[],
        ] {
            assert!(
                run_identity_with(&args(bad), &mut prompter).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(
            run_identity_with(&args(&["--help"]), &mut prompter)
                .unwrap()
                .code,
            0
        );
        assert_eq!(
            run_trust_with(&args(&["--help"]), &mut prompter)
                .unwrap()
                .code,
            0
        );
    }

    #[test]
    fn dashboard_operations_require_explicit_confirmation() {
        let _env = TestEnv::new("identity-dashboard");
        for body in [
            "",
            "{}",
            r#"{"confirm":false}"#,
            r#"{"confirm":"yes"}"#,
            r#"{"confirm":true,"x":1}"#,
        ] {
            assert!(dashboard_generate(body).is_err(), "{body}");
        }
        assert!(!dir().exists());
        let view: serde_json::Value =
            serde_json::from_str(&dashboard_generate(r#"{"confirm":true}"#).unwrap()).unwrap();
        assert_eq!(view["status"], "CONFIGURED");
        assert!(dashboard_reset("{}").is_err());

        let (text, public, _) = server_file("Server Roma", 1);
        let body = serde_json::json!({ "content": text }).to_string();
        let preview: serde_json::Value =
            serde_json::from_str(&dashboard_trust_preview(&body).unwrap()).unwrap();
        assert_eq!(preview["fingerprint"], fingerprint(&public));
        assert!(
            dashboard_trust_import(&body).is_err(),
            "import without confirmation"
        );
        let confirmed =
            serde_json::json!({ "content": text, "confirmFingerprint": fingerprint(&[2u8; 32]) });
        assert!(dashboard_trust_import(&confirmed.to_string()).is_err());
        let confirmed =
            serde_json::json!({ "content": text, "confirmFingerprint": fingerprint(&public) });
        let view: serde_json::Value =
            serde_json::from_str(&dashboard_trust_import(&confirmed.to_string()).unwrap()).unwrap();
        assert_eq!(view["trust"]["trusted"], 1);
        let id = server_id(&public);
        assert!(dashboard_trust_revoke(&id, "{}").is_err());
        dashboard_trust_revoke(&id, r#"{"confirm":true}"#).unwrap();
        assert!(dashboard_trust_clear("{}").is_err());
        let view: serde_json::Value =
            serde_json::from_str(&dashboard_trust_clear(r#"{"confirm":true}"#).unwrap()).unwrap();
        assert_eq!(view["trust"]["servers"].as_array().unwrap().len(), 0);
        assert_eq!(view["status"], "CONFIGURED");
    }

    #[test]
    fn time_format_is_utc_civil_date() {
        assert_eq!(format_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_time(1_798_675_200_000), "2026-12-31 00:00 UTC");
    }
}
