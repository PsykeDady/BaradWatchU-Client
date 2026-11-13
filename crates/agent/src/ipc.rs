//! Local IPC between the system service (`service run`) and per-user agents (`remote …`).
//!
//! Transport: a Unix domain socket (Linux/macOS) or a named pipe (Windows). Both ends
//! authenticate the peer through the operating system, never through data it sends:
//! - the service identifies every connecting user by kernel credentials (`SO_PEERCRED`,
//!   `getpeereid`, named-pipe client impersonation) and acts only for that user;
//! - the user agent accepts only a service that runs as root/LocalSystem (or as the user
//!   itself, which a user can only do to themselves: tests, development).
//!
//! Protocol `baradwatchu.ipc.v1`: one JSON object per line, at most `MAX_LINE` bytes.
//! Every connection starts with `Hello` and gets one `Reply`; a `LINK` connection then
//! stays open and only carries service → agent messages (`Job`, `Ping`). Job updates
//! travel on short connections of their own, so no handle is ever read and written
//! concurrently (Windows synchronous pipes serialize those operations).
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Read, Write};

pub(crate) const PROTOCOL: &str = "baradwatchu.ipc.v1";
pub(crate) const MAX_LINE: usize = 8 * 1024 * 1024;

/// Operating-system account of a local peer: `uid:<n>` (Unix) or `sid:<S-…>` (Windows).
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct Principal(pub(crate) String);

impl Principal {
    #[cfg(unix)]
    pub(crate) fn from_uid(uid: u32) -> Self {
        Self(format!("uid:{uid}"))
    }

    #[cfg(windows)]
    pub(crate) fn from_sid(sid: &str) -> Self {
        Self(format!("sid:{sid}"))
    }

    pub(crate) fn uid(&self) -> Option<u32> {
        self.0.strip_prefix("uid:")?.parse().ok()
    }

    pub(crate) fn sid(&self) -> Option<&str> {
        self.0.strip_prefix("sid:")
    }

    /// File stem for per-principal records: only `[A-Za-z0-9-]`, or None.
    pub(crate) fn file_stem(&self) -> Option<String> {
        let stem = self.0.replace(':', "-");
        (stem.len() <= 200 && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            .then_some(stem)
    }

    /// The account running this process.
    pub(crate) fn current() -> Option<Self> {
        #[cfg(unix)]
        {
            // SAFETY: geteuid has no preconditions.
            Some(Self::from_uid(unsafe { libc::geteuid() }))
        }
        #[cfg(windows)]
        {
            crate::identity::windows_acl::current_user_sid().map(|sid| Self::from_sid(&sid))
        }
    }

    /// root / LocalSystem.
    pub(crate) fn is_system(&self) -> bool {
        self.uid() == Some(0) || self.sid() == Some("S-1-5-18")
    }
}

/// State of a remote audit request, shared by the IPC and the remote API.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobState {
    PendingConsent,
    Running,
    Completed,
    Rejected,
    Expired,
    Busy,
    Unavailable,
    Failed,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::PendingConsent | Self::Running)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Intent {
    Register,
    Unregister,
    Status,
    Link,
    Update,
    Connection,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerConnectionStatus {
    pub server_id: String,
    pub endpoint: String,
    pub enabled: bool,
    pub connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The Server a job comes from, as verified by the service (mTLS key in the user's trust
/// store). The agent checks it again against its own trust store.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JobServer {
    pub server_id: String,
    pub public_key: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<crate::remote::Requester>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum ToService {
    #[serde(rename_all = "camelCase")]
    Hello {
        protocol: String,
        intent: Intent,
        /// `REGISTER`: the user's identity folder (the service checks it is theirs).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_dir: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_name: Option<String>,
        /// `UPDATE` fields.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<JobState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent_expires_at_unix_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
    },
}

impl ToService {
    pub(crate) fn hello(intent: Intent) -> Self {
        Self::Hello {
            protocol: PROTOCOL.into(),
            intent,
            identity_dir: None,
            client_name: None,
            job_id: None,
            state: None,
            consent_expires_at_unix_ms: None,
            reason: None,
            result: None,
            server_id: None,
            endpoint: None,
            action: None,
        }
    }
}

/// What the service reports to a user agent about itself and that user.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceStatus {
    pub version: String,
    pub registered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_device_id: Option<String>,
    /// The registration no longer matches the identity on disk (reset, damaged, unsafe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_problem: Option<String>,
    pub session_linked: bool,
    pub request_in_progress: bool,
    #[serde(default)]
    pub connections: Vec<ServerConnectionStatus>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum ToAgent {
    #[serde(rename_all = "camelCase")]
    Reply {
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<ServiceStatus>,
    },
    #[serde(rename_all = "camelCase")]
    Job {
        job_id: String,
        device_id: String,
        server: JobServer,
    },
    Ping,
}

impl ToAgent {
    pub(crate) fn ok(status: Option<ServiceStatus>) -> Self {
        Self::Reply {
            ok: true,
            error: None,
            status,
        }
    }

    pub(crate) fn error(message: &str) -> Self {
        Self::Reply {
            ok: false,
            error: Some(message.into()),
            status: None,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------------------

pub(crate) fn write_message<W: Write, T: Serialize>(writer: &mut W, message: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(message).map_err(io::Error::other)?;
    if line.len() >= MAX_LINE {
        return Err(io::Error::other("IPC message too large"));
    }
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()
}

/// Reads one bounded line; `Ok(None)` on a clean end of stream.
pub(crate) fn read_message<R: BufRead, T: DeserializeOwned>(
    reader: &mut R,
) -> io::Result<Option<T>> {
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC line too long or truncated",
        ));
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

// ---------------------------------------------------------------------------------------
// Endpoint location
// ---------------------------------------------------------------------------------------

/// `BARADWATCHU_SERVICE_SOCKET` (tests, development) or the platform default.
pub(crate) fn endpoint() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("BARADWATCHU_SERVICE_SOCKET").filter(|v| !v.is_empty()) {
        return path.into();
    }
    if cfg!(windows) {
        r"\\.\pipe\baradwatchu-agent".into()
    } else if cfg!(target_os = "macos") {
        "/var/run/baradwatchu/agent.sock".into()
    } else {
        "/run/baradwatchu/agent.sock".into()
    }
}

// ---------------------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub(crate) type Stream = std::fs::File;

/// One authenticated connection.
pub(crate) struct Connection {
    reader: BufReader<Stream>,
    writer: Stream,
    pub(crate) peer: Principal,
}

impl Connection {
    pub(crate) fn send<T: Serialize>(&mut self, message: &T) -> io::Result<()> {
        write_message(&mut self.writer, message)
    }

    pub(crate) fn receive<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        read_message(&mut self.reader)
    }

    /// Splits off the write half (the service keeps it to push jobs to a linked agent).
    pub(crate) fn into_writer(self) -> Stream {
        self.writer
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<std::time::Duration>) {
        #[cfg(unix)]
        let _ = self.reader.get_ref().set_read_timeout(timeout);
        #[cfg(windows)]
        let _ = timeout; // pipes: the peer's disconnection ends a blocked read
    }
}

/// Rights of Authenticated Users on the service pipe: SYNCHRONIZE | READ_CONTROL |
/// FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES |
/// FILE_WRITE_ATTRIBUTES (no FILE_CREATE_PIPE_INSTANCE).
#[cfg(windows)]
const USER_PIPE_ACCESS: u32 = 0x0012_018b;

/// Connects to the local service and checks who runs it.
pub(crate) fn connect() -> io::Result<Connection> {
    let path = endpoint();
    #[cfg(unix)]
    let stream = std::os::unix::net::UnixStream::connect(&path)?;
    // Ask exactly for the rights the pipe grants to users (`USER_PIPE_ACCESS`). Plain
    // `.write(true)` asks GENERIC_WRITE, which includes FILE_CREATE_PIPE_INSTANCE (withheld on
    // purpose) and was therefore denied: no user agent could reach the service.
    #[cfg(windows)]
    let stream = {
        use std::os::windows::fs::OpenOptionsExt;
        // SECURITY_IDENTIFICATION: the service must read this account from its impersonation
        // token. Recent Rust std opens files with SECURITY_ANONYMOUS by default, which made
        // the service drop every connection; identification lets it know who is calling
        // without letting it act as that user.
        const SECURITY_IDENTIFICATION: u32 = 1 << 16;
        std::fs::OpenOptions::new()
            .access_mode(USER_PIPE_ACCESS)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&path)?
    };
    let peer = peer_of_service(&stream)?;
    let me = Principal::current().ok_or_else(|| io::Error::other("unknown local account"))?;
    if !peer.is_system() && peer != me {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the local service endpoint is not owned by the system",
        ));
    }
    let writer = stream.try_clone()?;
    Ok(Connection {
        reader: BufReader::new(stream),
        writer,
        peer,
    })
}

/// One request/reply exchange on a fresh connection.
pub(crate) fn call(message: &ToService) -> io::Result<ToAgent> {
    let mut connection = connect()?;
    connection.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    connection.send(message)?;
    connection.receive()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "service closed the connection",
        )
    })
}

#[cfg(unix)]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: valid socket descriptor and a correctly sized output buffer.
        let status = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(credentials.uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: valid socket descriptor and output pointers.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

#[cfg(unix)]
fn peer_of_service(stream: &Stream) -> io::Result<Principal> {
    peer_uid(stream).map(Principal::from_uid)
}

#[cfg(unix)]
pub(crate) fn peer_of_client(stream: &Stream) -> io::Result<Principal> {
    peer_uid(stream).map(Principal::from_uid)
}

#[cfg(windows)]
fn peer_of_service(stream: &Stream) -> io::Result<Principal> {
    windows_pipe::server_principal(stream)
}

#[cfg(windows)]
pub(crate) fn peer_of_client(stream: &Stream) -> io::Result<Principal> {
    windows_pipe::client_principal(stream)
}

// ---------------------------------------------------------------------------------------
// Service side: listening endpoint
// ---------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) struct Listener(std::os::unix::net::UnixListener);

#[cfg(unix)]
impl Listener {
    /// Binds the socket; its folder is created owner-writable and world-traversable, the
    /// socket itself world-connectable (authorization happens per connection).
    pub(crate) fn bind() -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let path = endpoint();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(io::Error::other("unsafe service socket folder"));
            }
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || metadata.is_file() || metadata.is_dir() =>
            {
                return Err(io::Error::other("service socket path is occupied"));
            }
            Ok(_) => std::fs::remove_file(&path)?,
            Err(_) => {}
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        Ok(Self(listener))
    }

    pub(crate) fn accept(&self) -> io::Result<Connection> {
        let (stream, _) = self.0.accept()?;
        let peer = peer_of_client(&stream)?;
        let writer = stream.try_clone()?;
        Ok(Connection {
            reader: BufReader::new(stream),
            writer,
            peer,
        })
    }
}

#[cfg(windows)]
pub(crate) struct Listener {
    first: std::sync::atomic::AtomicBool,
}

#[cfg(windows)]
impl Listener {
    pub(crate) fn bind() -> io::Result<Self> {
        Ok(Self {
            first: std::sync::atomic::AtomicBool::new(true),
        })
    }

    pub(crate) fn accept(&self) -> io::Result<Connection> {
        let first = self.first.swap(false, std::sync::atomic::Ordering::SeqCst);
        let stream = windows_pipe::accept(&endpoint(), first)?;
        let peer = peer_of_client(&stream)?;
        let writer = stream.try_clone()?;
        Ok(Connection {
            reader: BufReader::new(stream),
            writer,
            peer,
        })
    }
}

#[cfg(windows)]
mod windows_pipe {
    //! Named pipe server and peer identification (Win32). Compiled for Windows only; not
    //! exercised on this development host (see README, platform status).
    use super::Principal;
    use std::{
        fs::File,
        io,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::Path,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
            },
            GetTokenInformation, RevertToSelf, TokenUser, OWNER_SECURITY_INFORMATION,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    };

    /// SYSTEM: full control; Authenticated Users: read/write data only (no
    /// FILE_CREATE_PIPE_INSTANCE, so no user can add a squatting instance).
    const PIPE_DACL: &str = "D:P(A;;GA;;;SY)(A;;0x12018b;;;AU)";
    // The client opens with exactly this mask; keep both in sync.
    const _: () = assert!(super::USER_PIPE_ACCESS == 0x0012_018b);

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn accept(path: &Path, first: bool) -> io::Result<File> {
        let name: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // The service (LocalSystem) names SYSTEM as the pipe's owner: that owner is what user
        // agents verify, and no ordinary account can create an object owned by SYSTEM. A
        // console run by a user (development) keeps that user as the default owner.
        let system = Principal::current().is_some_and(|me| me.is_system());
        let sddl = wide(&if system {
            format!("O:SY{PIPE_DACL}")
        } else {
            PIPE_DACL.to_owned()
        });
        // SAFETY: the descriptor is freed after CreateNamedPipeW copied it; the returned
        // handle is owned by the File built from it.
        unsafe {
            let mut descriptor = ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    },
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &attributes,
            );
            LocalFree(descriptor);
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            if ConnectNamedPipe(handle, ptr::null_mut()) == 0
                && GetLastError() != ERROR_PIPE_CONNECTED
            {
                let error = io::Error::last_os_error();
                CloseHandle(handle);
                return Err(error);
            }
            Ok(File::from_raw_handle(handle as _))
        }
    }

    /// SAFETY: `token` must be a valid token handle opened with TOKEN_QUERY.
    unsafe fn token_sid(token: HANDLE) -> Option<String> {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
            || buffer.len() < std::mem::size_of::<TOKEN_USER>()
        {
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

    /// The connected client's account, read from its impersonation token.
    pub(super) fn client_principal(pipe: &File) -> io::Result<Principal> {
        // SAFETY: impersonation is reverted before returning; the token handle is closed.
        unsafe {
            if ImpersonateNamedPipeClient(pipe.as_raw_handle() as HANDLE) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut token: HANDLE = ptr::null_mut();
            let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) != 0;
            RevertToSelf();
            if !opened {
                return Err(io::Error::last_os_error());
            }
            let sid = token_sid(token);
            CloseHandle(token);
            sid.map(|sid| Principal::from_sid(&sid))
                .ok_or_else(|| io::Error::other("cannot identify the pipe client"))
        }
    }

    /// The owner of the pipe (expected: LocalSystem, set by the service when it creates it).
    /// Not the server process's token: an ordinary user may not open the token of a
    /// LocalSystem process, so that check always failed for the agents it protects.
    pub(super) fn server_principal(pipe: &File) -> io::Result<Principal> {
        // SAFETY: the owner SID points into the descriptor, which is freed after conversion.
        unsafe {
            let mut owner = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            let status = GetSecurityInfo(
                pipe.as_raw_handle() as HANDLE,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            );
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let mut text = ptr::null_mut::<u16>();
            let converted = !owner.is_null() && ConvertSidToStringSidW(owner, &mut text) != 0;
            LocalFree(descriptor);
            if !converted || text.is_null() {
                return Err(io::Error::other("cannot identify the pipe owner"));
            }
            let mut length = 0;
            while *text.add(length) != 0 {
                length += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
            LocalFree(text.cast());
            Ok(Principal::from_sid(&sid))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips_and_bounds_lines() {
        let mut buffer = Vec::new();
        write_message(&mut buffer, &ToAgent::Ping).unwrap();
        write_message(&mut buffer, &ToService::hello(Intent::Status)).unwrap();
        let mut reader = io::Cursor::new(buffer);
        assert!(matches!(
            read_message::<_, ToAgent>(&mut reader).unwrap(),
            Some(ToAgent::Ping)
        ));
        let hello: ToService = read_message(&mut reader).unwrap().unwrap();
        let ToService::Hello {
            protocol, intent, ..
        } = hello;
        assert_eq!((protocol.as_str(), intent), (PROTOCOL, Intent::Status));
        assert!(read_message::<_, ToAgent>(&mut reader).unwrap().is_none());
        // Unknown fields and unterminated lines are refused.
        let mut bad = io::Cursor::new(b"{\"type\":\"reply\",\"ok\":true,\"x\":1}\n".to_vec());
        assert!(read_message::<_, ToAgent>(&mut bad).is_err());
        let mut cut = io::Cursor::new(b"{\"type\":\"ping\"}".to_vec());
        assert!(read_message::<_, ToAgent>(&mut cut).is_err());
    }

    #[test]
    fn principals_have_safe_file_stems() {
        assert_eq!(
            Principal("uid:1000".into()).file_stem().as_deref(),
            Some("uid-1000")
        );
        assert!(Principal("uid:0".into()).is_system());
        assert!(Principal("sid:S-1-5-18".into()).is_system());
        assert_eq!(Principal("uid:../x".into()).file_stem(), None);
    }
}
