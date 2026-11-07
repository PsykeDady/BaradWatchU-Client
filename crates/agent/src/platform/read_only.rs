//! Child-only filesystem restriction. Optional write access is limited to the real null device.
use std::io;

#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// Only syscalls here: called after fork, before exec in a possibly threaded caller.
pub(super) fn restrict(allow_null: bool) -> io::Result<()> {
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
    if allow_null {
        // SAFETY: fixed NUL-terminated path; O_PATH and O_NOFOLLOW ensure that
        // the rule is anchored to the inspected device, not a symlink target.
        let null = unsafe {
            libc::open(
                c"/dev/null".as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        // SAFETY: zeroed stat is a valid output buffer for fstat.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let valid = null >= 0
            && unsafe { libc::fstat(null, &mut stat) } == 0
            && stat.st_mode & libc::S_IFMT == libc::S_IFCHR
            && libc::major(stat.st_rdev) == 1
            && libc::minor(stat.st_rdev) == 3;
        let rule = PathBeneath {
            allowed_access: 1 << 1, // WRITE_FILE only; not truncate/create/remove
            parent_fd: null,
        };
        let added =
            valid && unsafe { libc::syscall(libc::SYS_landlock_add_rule, fd, 1, &rule, 0) } == 0;
        if null >= 0 {
            unsafe { libc::close(null) };
        }
        if !added {
            unsafe { libc::close(fd as i32) };
            return Err(unavailable());
        }
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
