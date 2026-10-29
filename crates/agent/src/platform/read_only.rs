//! Child-only filesystem restriction. No rules grant writes anywhere; reads/exec remain allowed.
use std::io;

#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
}

/// Only syscalls here: called after fork, before exec in a possibly threaded caller.
pub(super) fn restrict() -> io::Result<()> {
    // Landlock ABI 3 includes REFER and TRUNCATE. Refuse older or disabled kernels.
    // All mutation rights through ABI 3; intentionally excludes EXECUTE/READ_FILE/READ_DIR.
    const MUTATIONS: u64 = ((1 << 15) - 1) & !((1 << 0) | (1 << 2) | (1 << 3));
    let unavailable = || io::Error::from_raw_os_error(libc::EOPNOTSUPP);
    // SAFETY: the ABI query uses the documented null pointer/zero size and VERSION flag.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<Ruleset>(),
            0,
            1,
        )
    };
    if abi < 3 {
        return Err(unavailable());
    }
    let ruleset = Ruleset {
        handled_access_fs: MUTATIONS,
    };
    // SAFETY: pointer/size match the repr(C) ruleset; kernel copies it during the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if fd < 0 {
        return Err(unavailable());
    }
    // SAFETY: documented prctl arguments; fd belongs to this child. Closing it does not
    // remove an installed restriction. No inherited descriptor is made writable here.
    let applied = unsafe {
        let applied = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::syscall(libc::SYS_landlock_restrict_self, fd, 0) == 0;
        libc::close(fd as i32);
        applied
    };
    if applied {
        Ok(())
    } else {
        Err(unavailable())
    }
}
