//! Bounded subprocess collection. Fixed native probes supply commands; never a shell.
use crate::audit::Reason;
use std::{
    io::{self, Read},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct ProbeError {
    pub reason: Reason,
    pub message: String,
}
impl ProbeError {
    pub fn new(reason: Reason, message: &str) -> Self {
        Self {
            reason,
            message: message.to_owned(),
        }
    }
    pub fn io(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => {
                Self::new(Reason::MissingTool, "Required inspection tool is missing")
            }
            io::ErrorKind::PermissionDenied => Self::new(
                Reason::PermissionDenied,
                "Inspection denied by caller permissions",
            ),
            _ => Self::new(Reason::ExecutionFailed, "Inspection process or I/O failed"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub output_limit: usize,
    /// Mandatory for tools that could write logs/cache during nominally read-only queries.
    pub read_only_filesystem: bool,
}
impl CommandSpec {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            timeout: Duration::from_secs(30),
            output_limit: 256 * 1024,
            read_only_filesystem: false,
        }
    }
}
#[derive(Debug)]
pub struct CommandOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}
pub trait CommandRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ProbeError>;
}
pub struct SystemRunner;

fn reader(
    mut stream: impl Read + Send + 'static,
    limit: usize,
    exceeded: Arc<AtomicBool>,
) -> io::Result<mpsc::Receiver<io::Result<Vec<u8>>>> {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        let result = loop {
            match stream.read(&mut buffer) {
                Ok(0) => break Ok(bytes),
                Ok(count) => {
                    if count > limit.saturating_sub(bytes.len()) {
                        exceeded.store(true, Ordering::Relaxed);
                    }
                    let keep = count.min(limit.saturating_sub(bytes.len()));
                    bytes.extend_from_slice(&buffer[..keep]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => break Err(error),
            }
        };
        let _ = tx.send(result);
    })?;
    Ok(rx)
}

fn stop(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // process_group(0) creates a group owned by this invocation, including tool children.
        // SAFETY: negative PID addresses that owned process group; no pointer arguments.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl CommandRunner for SystemRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        if spec.read_only_filesystem {
            // Report missing tooling even on a host where Landlock is unavailable.
            std::fs::metadata(&spec.program).map_err(ProbeError::io)?;
        }
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .current_dir("/")
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("TZ", "UTC")
            .env("DNF5_PLUGINS_DIR", "")
            .env("DNF5_FORCE_INTERACTIVE", "0")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let owner = std::process::id() as libc::pid_t;
            // SAFETY: async-signal-safe syscalls only; kills this probe if its
            // spawning agent dies, including a Ctrl-C before the normal timeout.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != owner {
                        return Err(io::Error::from_raw_os_error(libc::EINTR));
                    }
                    Ok(())
                });
            }
        }
        if spec.read_only_filesystem {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::process::CommandExt;
                // SAFETY: the hook only invokes async-signal-safe syscalls and creates
                // errors from a constant errno; it performs no allocation or locking.
                unsafe {
                    command.pre_exec(super::read_only::restrict);
                }
            }
            #[cfg(not(target_os = "linux"))]
            return Err(ProbeError::new(
                Reason::ReadOnlyGuardUnavailable,
                "Read-only inspection guard requires Linux Landlock ABI 3+",
            ));
        }
        let mut child = command.spawn().map_err(|error| {
            #[cfg(target_os = "linux")]
            if spec.read_only_filesystem && error.raw_os_error() == Some(libc::EOPNOTSUPP) {
                return ProbeError::new(Reason::ReadOnlyGuardUnavailable,
                    "Cannot enforce read-only probe: Linux Landlock ABI 3+ must be enabled and permitted; no unsafe retry");
            }
            ProbeError::io(error)
        })?;
        let exceeded = Arc::new(AtomicBool::new(false));
        let pipes = (|| {
            let stdout = reader(
                child.stdout.take().expect("piped stdout"),
                spec.output_limit,
                exceeded.clone(),
            )?;
            let stderr = reader(
                child.stderr.take().expect("piped stderr"),
                spec.output_limit,
                exceeded.clone(),
            )?;
            Ok::<_, io::Error>((stdout, stderr))
        })();
        let (stdout, stderr) = match pipes {
            Ok(pipes) => pipes,
            Err(error) => {
                stop(&mut child);
                return Err(ProbeError::io(error));
            }
        };
        let start = Instant::now();
        let status = loop {
            if exceeded.load(Ordering::Relaxed) {
                stop(&mut child);
                return Err(ProbeError::new(
                    Reason::OutputLimit,
                    "Inspection output exceeded the collection limit",
                ));
            }
            if start.elapsed() >= spec.timeout {
                stop(&mut child);
                return Err(ProbeError::new(
                    Reason::Timeout,
                    "Inspection exceeded its execution deadline",
                ));
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    stop(&mut child);
                    return Err(ProbeError::io(error));
                }
            }
        };
        let collect = |rx: mpsc::Receiver<io::Result<Vec<u8>>>| {
            let bytes = rx
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| {
                    ProbeError::new(
                        Reason::ExecutionFailed,
                        "Inspection output stream did not close",
                    )
                })?
                .map_err(ProbeError::io)?;
            String::from_utf8(bytes).map_err(|_| {
                ProbeError::new(Reason::InvalidOutput, "Inspection returned invalid UTF-8")
            })
        };
        let result = (|| {
            Ok(CommandOutput {
                code: status.code(),
                stdout: collect(stdout)?,
                stderr: collect(stderr)?,
            })
        })();
        // Also clean up children of an exited command; they must not survive a probe.
        stop(&mut child);
        if exceeded.load(Ordering::Relaxed) {
            return Err(ProbeError::new(
                Reason::OutputLimit,
                "Inspection output exceeded the collection limit",
            ));
        }
        result
    }
}
