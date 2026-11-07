//! Independent kernel backing-device evidence. UUIDs are inspected but never reported.
use crate::{audit::Reason, platform::command::ProbeError};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct KernelDevice {
    pub parents: Vec<String>,
    pub kind: String,
    pub luks_mapping: bool,
}
pub trait KernelTopology {
    fn inspect(&self, device: &str) -> Result<Option<KernelDevice>, ProbeError>;
}
pub struct SysfsTopology;

pub(super) fn valid_device(value: &str) -> bool {
    value.split_once(':').is_some_and(|(major, minor)| {
        !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|v| v.is_ascii_digit())
            && minor.bytes().all(|v| v.is_ascii_digit())
            && major.parse::<u32>().is_ok()
            && minor.parse::<u32>().is_ok()
    })
}
fn read(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    fs::File::open(path)?.take(4097).read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Oversized sysfs value",
        ));
    }
    Ok(text.trim().to_owned())
}
fn exists(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
fn device(path: PathBuf) -> io::Result<String> {
    let id = read(&path)?;
    if !valid_device(&id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid kernel device identifier",
        ));
    }
    Ok(id)
}
impl KernelTopology for SysfsTopology {
    fn inspect(&self, id: &str) -> Result<Option<KernelDevice>, ProbeError> {
        if !valid_device(id) {
            return Err(ProbeError::new(
                Reason::InvalidOutput,
                "Invalid device identifier",
            ));
        }
        let inspect = || -> io::Result<KernelDevice> {
            let root = Path::new("/sys/dev/block").join(id);
            fs::metadata(&root)?;
            if exists(&root.join("partition"))? {
                let resolved = fs::canonicalize(&root)?;
                let parent = resolved.parent().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Partition parent missing")
                })?;
                return Ok(KernelDevice {
                    parents: vec![device(parent.join("dev"))?],
                    kind: "part".into(),
                    luks_mapping: false,
                });
            }
            let mut parents = vec![];
            for entry in fs::read_dir(root.join("slaves"))? {
                parents.push(device(entry?.path().join("dev"))?);
            }
            parents.sort();
            parents.dedup();
            let (kind, luks_mapping) = if exists(&root.join("dm"))? {
                let uuid = read(&root.join("dm/uuid"))?;
                if uuid.starts_with("CRYPT-LUKS1-") || uuid.starts_with("CRYPT-LUKS2-") {
                    ("crypt", true)
                } else if uuid.starts_with("CRYPT-PLAIN-") {
                    ("crypt", false)
                } else if uuid.starts_with("LVM-") {
                    ("lvm", false)
                } else {
                    ("dm", false)
                }
            } else if exists(&root.join("loop"))? {
                ("loop", false)
            } else if exists(&root.join("md"))? {
                ("raid", false)
            } else {
                ("disk", false)
            };
            Ok(KernelDevice {
                parents,
                kind: kind.into(),
                luks_mapping,
            })
        };
        match inspect() {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => Err(ProbeError::new(
                Reason::InvalidOutput,
                "Invalid kernel topology metadata",
            )),
            Err(error) => Err(ProbeError::io(error)),
        }
    }
}
