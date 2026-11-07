//! Bounded reads and permission metadata only. Never open TPM device nodes.
use crate::{audit::Reason, platform::command::ProbeError};
use std::{fs, io::Read, path::Path};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Directory,
    Regular,
    Character,
    Socket,
    Other,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub kind: NodeKind,
    pub major: u32,
    pub minor: u32,
    pub readable: bool,
    pub owner: u32,
    pub size: u64,
    pub modified_ns: Option<u128>,
    pub inode: u64,
}
pub trait Files {
    fn read(&self, path: &str, limit: usize) -> Result<Option<Vec<u8>>, ProbeError>;
    fn info(&self, path: &str) -> Result<Option<Node>, ProbeError>;
    fn entries(&self, path: &str) -> Result<Option<Vec<String>>, ProbeError>;
}
pub struct SystemFiles;
impl Files for SystemFiles {
    fn read(&self, path: &str, limit: usize) -> Result<Option<Vec<u8>>, ProbeError> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ProbeError::io(e)),
        };
        if !file.metadata().map_err(ProbeError::io)?.is_file() {
            return Err(ProbeError::new(
                Reason::InvalidOutput,
                "Inspection source is not a regular kernel/configuration file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(ProbeError::io)?;
        if bytes.len() > limit {
            return Err(ProbeError::new(
                Reason::OutputLimit,
                "Inspection file exceeds bounded read limit",
            ));
        }
        Ok(Some(bytes))
    }
    fn info(&self, path: &str) -> Result<Option<Node>, ProbeError> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let m = match fs::metadata(Path::new(path)) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ProbeError::io(e)),
        };
        let c = std::ffi::CString::new(path)
            .map_err(|_| ProbeError::new(Reason::InvalidOutput, "Invalid metadata path"))?;
        // SAFETY: valid NUL-terminated path. This checks permissions; no device is opened.
        let readable =
            unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::R_OK, libc::AT_EACCESS) }
                == 0;
        Ok(Some(Node {
            kind: if m.is_dir() {
                NodeKind::Directory
            } else if m.is_file() {
                NodeKind::Regular
            } else if m.file_type().is_char_device() {
                NodeKind::Character
            } else if m.file_type().is_socket() {
                NodeKind::Socket
            } else {
                NodeKind::Other
            },
            major: libc::major(m.rdev()),
            minor: libc::minor(m.rdev()),
            readable,
            owner: m.uid(),
            size: m.len(),
            modified_ns: m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos()),
            inode: m.ino(),
        }))
    }
    fn entries(&self, path: &str) -> Result<Option<Vec<String>>, ProbeError> {
        let directory = match fs::read_dir(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ProbeError::io(e)),
        };
        let mut names = Vec::new();
        for entry in directory {
            if names.len() >= 64 {
                return Err(ProbeError::new(
                    Reason::OutputLimit,
                    "Too many inspection directory entries",
                ));
            }
            let entry = entry.map_err(ProbeError::io)?;
            names.push(entry.file_name().into_string().map_err(|_| {
                ProbeError::new(Reason::InvalidOutput, "Invalid kernel entry name")
            })?);
        }
        names.sort();
        Ok(Some(names))
    }
}
pub fn text(files: &dyn Files, path: &str, limit: usize) -> Result<Option<String>, ProbeError> {
    files
        .read(path, limit)?
        .map(|b| {
            String::from_utf8(b).map_err(|_| {
                ProbeError::new(Reason::InvalidOutput, "Invalid UTF8 inspection metadata")
            })
        })
        .transpose()
}
