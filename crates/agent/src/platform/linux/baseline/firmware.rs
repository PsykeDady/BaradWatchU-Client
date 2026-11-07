//! Firmware state from cached kernel attributes, not privileged firmware/TPM commands.
use super::{
    context, error,
    files::{self, Files, NodeKind},
    host, observed,
};
use crate::{
    audit::{Outcome, Reason},
    observation::{BootState, Observation, Quality, SecureBoot, Tpm, TpmDevice},
    platform::{command::ProbeError, linux::environment::Environment},
};
const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
fn boot_result(f: SecureBoot, message: &str) -> Outcome {
    let positive = match f.state {
        BootState::Enabled => Some(true),
        BootState::Disabled | BootState::NonUefiBoot => Some(false),
        _ => None,
    };
    observed(
        Observation::SecureBoot(f.clone()),
        f.quality,
        positive,
        "Linux efivarfs SecureBoot + SetupMode (EFI global GUID)",
        "kernel-reported UEFI state only; no independent boot-chain/module verification",
        message,
    )
}
fn variable(files: &dyn Files, name: &str) -> Result<Option<bool>, ProbeError> {
    let Some(bytes) = files.read(&format!("/sys/firmware/efi/efivars/{name}-{GUID}"), 8)? else {
        return Ok(None);
    };
    if bytes.len() != 5
        || bytes[4] > 1
        || u32::from_le_bytes(bytes[..4].try_into().expect("four bytes")) & 6 != 6
    {
        return Err(ProbeError::new(
            Reason::InvalidOutput,
            "Malformed EFI boolean variable/attributes",
        ));
    }
    Ok(Some(bytes[4] == 1))
}
pub fn secure_boot(files: &dyn Files, env: &Environment) -> Outcome {
    let mut f = SecureBoot {
        quality: Quality::Restricted,
        state: BootState::Restricted,
        secure_boot: None,
        setup_mode: None,
    };
    if !host(env) {
        return context(
            boot_result(
                f,
                "Host firmware scope unavailable in container/unknown context",
            ),
            env,
        );
    }
    f.quality = Quality::Missing;
    f.state = BootState::VariablesUnavailable;
    let inspect = || -> Result<SecureBoot, ProbeError> {
        let mut f = f.clone();
        if !matches!(files.info("/sys/firmware")?,Some(n) if n.kind==NodeKind::Directory) {
            return Ok(f);
        }
        if files.info("/sys/firmware/efi")?.is_none() {
            f.quality = Quality::Verified;
            f.state = BootState::NonUefiBoot;
            return Ok(f);
        }
        f.secure_boot = variable(files, "SecureBoot")?;
        f.setup_mode = variable(files, "SetupMode")?;
        match (f.secure_boot, f.setup_mode) {
            (Some(true), Some(false)) => {
                f.quality = Quality::Verified;
                f.state = BootState::Enabled
            }
            (Some(false), Some(_)) => {
                f.quality = Quality::Verified;
                f.state = BootState::Disabled
            }
            (Some(true), Some(true)) => {
                f.quality = Quality::Inconclusive;
                f.state = BootState::Inconsistent
            }
            _ => {}
        }
        Ok(f)
    };
    context(
        match inspect() {
            Ok(f) => boot_result(
                f,
                "EFI variable observation; missing/contradictory variables do not prove enablement",
            ),
            Err(e) => error(boot_result(f, "EFI variables unavailable"), e),
        },
        env,
    )
}
fn tpm_result(f: Tpm, message: &str) -> Outcome {
    let positive = if f.quality == Quality::Verified {
        Some(f.devices.iter().any(|d| {
            d.version_major == Some(2)
                && d.character_device_verified
                && d.read_permission == Some(true)
        }))
    } else {
        None
    };
    observed(Observation::Tpm(f.clone()),f.quality,positive,"/sys/class/tpm/*/{tpm_version_major,dev}, tpmrm metadata and /dev permissions","kernel-exposed version/device read permission only; no TPM open/commands/keys/PCR/attestation",message)
}
fn pair(text: &str) -> Option<(u32, u32)> {
    let (a, b) = text.trim().split_once(':')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}
fn access(files: &dyn Files, sys: &str, dev: &str) -> Result<(bool, Option<bool>), ProbeError> {
    let Some(id) = files::text(files, sys, 64)? else {
        return Ok((false, None));
    };
    let id = pair(&id)
        .ok_or_else(|| ProbeError::new(Reason::InvalidOutput, "Malformed TPM device identifier"))?;
    match files.info(dev)? {
        Some(n) if n.kind == NodeKind::Character && (n.major, n.minor) == id => {
            Ok((true, Some(n.readable)))
        }
        _ => Ok((false, None)),
    }
}
pub fn tpm(files: &dyn Files, env: &Environment) -> Outcome {
    let empty = Tpm {
        quality: if host(env) {
            Quality::Missing
        } else {
            Quality::Restricted
        },
        devices: vec![],
    };
    if !host(env) {
        return context(
            tpm_result(
                empty,
                "Host TPM scope unavailable in container/unknown context",
            ),
            env,
        );
    }
    let inspect = || -> Result<Tpm, ProbeError> {
        let Some(names) = files.entries("/sys/class/tpm")? else {
            return Ok(empty.clone());
        };
        let mut f = Tpm {
            quality: Quality::Verified,
            devices: vec![],
        };
        for name in names {
            let Some(index) = name
                .strip_prefix("tpm")
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            else {
                return Err(ProbeError::new(
                    Reason::InvalidOutput,
                    "Unexpected TPM class entry",
                ));
            };
            if f.devices.len() >= 16 {
                return Err(ProbeError::new(Reason::OutputLimit, "Too many TPM devices"));
            }
            let version = files::text(
                files,
                &format!("/sys/class/tpm/{name}/tpm_version_major"),
                32,
            )?
            .map(|v| {
                v.trim().parse::<u32>().map_err(|_| {
                    ProbeError::new(Reason::InvalidOutput, "Malformed kernel TPM version")
                })
            })
            .transpose()?;
            let mut node = access(
                files,
                &format!("/sys/class/tpm/{name}/dev"),
                &format!("/dev/{name}"),
            )?;
            // Resource manager may be accessible even when the raw device is not.
            if version == Some(2) && node.1 != Some(true) {
                let rm = access(
                    files,
                    &format!("/sys/class/tpmrm/tpmrm{index}/dev"),
                    &format!("/dev/tpmrm{index}"),
                )?;
                if rm.0 && rm.1 == Some(true) {
                    node = rm
                }
            }
            if !matches!(version, Some(1 | 2)) || !node.0 || node.1 != Some(true) {
                f.quality = Quality::Inconclusive
            }
            f.devices.push(TpmDevice {
                version_major: version,
                character_device_verified: node.0,
                read_permission: node.1,
            });
        }
        Ok(f)
    };
    context(match inspect(){Ok(f)=>tpm_result(f,"TPM enumeration/access observation; presence does not establish encryption or measured boot"),Err(e)=>error(tpm_result(empty,"TPM metadata unavailable"),e)},env)
}
