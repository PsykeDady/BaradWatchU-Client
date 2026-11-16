// Stage the approved data file beside Cargo artifacts using the installed layout.
// Runtime never needs the checkout or a compile-time absolute source path.
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("Create staged data directory");
    for entry in fs::read_dir(source).expect("Read source data directory") {
        let entry = entry.expect("Read source data entry");
        let source_path = entry.path();
        let target_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).expect("Inspect source data entry");
        assert!(
            !metadata.file_type().is_symlink(),
            "Symbolic links are not allowed in installed data"
        );
        if metadata.is_dir() {
            copy_tree(&source_path, &target_path);
        } else if metadata.is_file() {
            fs::copy(&source_path, &target_path).expect("Stage source data file");
        } else {
            panic!("Unsupported source data entry");
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=../../catalog");
    println!("cargo:rerun-if-changed=../../catalog/checks");
    println!("cargo:rerun-if-changed=../../catalog/checks-windows");
    println!("cargo:rerun-if-changed=../../catalog/checks-macos");
    println!("cargo:rerun-if-changed=../../web/src");
    println!("cargo:rerun-if-changed=../../web/dist/client-status/browser");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let catalog = manifest.join("../../catalog");
    let web = manifest.join("../../web/dist/client-status/browser");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // OUT_DIR is <profile>/build/<pkg>-<hash>/out (Cargo <= 1.99) or
    // <profile>/build/<pkg>/<hash>/out (build-dir layout of Cargo 1.100): the profile folder is
    // the parent of the nearest "build" ancestor in both.
    let profile = out
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
        .expect("Cargo profile output directory");
    // In-crate unit tests locate the staged installation through this path: with the Cargo
    // 1.100 layout their executables no longer live in profile/deps/.
    println!(
        "cargo:rustc-env=BARADWATCHU_TEST_INSTALL_ROOT={}",
        profile.display()
    );
    // Main binaries live in profile/, test executables in profile/deps/.
    // Only the target OS's builtin checks are staged: Linux `catalog/checks`, Windows
    // `catalog/checks-windows`, macOS `catalog/checks-macos`. The hash manifest covers all of
    // them and is staged as is.
    const CHECK_DIRS: [&str; 3] = ["checks", "checks-windows", "checks-macos"];
    let own_checks = match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("windows") => "checks-windows",
        Ok("macos") => "checks-macos",
        _ => "checks",
    };
    let is_other_checks = |name: &std::ffi::OsStr| {
        CHECK_DIRS
            .iter()
            .any(|dir| *dir != own_checks && name == std::ffi::OsStr::new(dir))
    };
    for prefix in [profile.parent().unwrap(), profile] {
        let target = prefix.join("share/baradwatchu-client");
        let staged_catalog = target.join("catalog");
        // Rebuild the staged check folders from scratch: a file removed from the source tree
        // must not linger, since every audit reports files the manifest does not list.
        let staged_checks = staged_catalog.join(own_checks);
        if fs::symlink_metadata(&staged_checks)
            .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
        {
            fs::remove_dir_all(&staged_checks).expect("Remove stale staged checks");
        }
        fs::create_dir_all(&staged_catalog).expect("Create staged catalog directory");
        for entry in fs::read_dir(&catalog).expect("Read catalog directory") {
            let entry = entry.expect("Read catalog entry");
            let name = entry.file_name();
            let source_path = entry.path();
            let metadata = fs::symlink_metadata(&source_path).expect("Inspect catalog entry");
            assert!(
                !metadata.file_type().is_symlink(),
                "Symbolic links are not allowed in installed data"
            );
            if is_other_checks(&name) {
                continue;
            }
            if metadata.is_dir() {
                copy_tree(&source_path, &staged_catalog.join(&name));
            } else if metadata.is_file() {
                fs::copy(&source_path, staged_catalog.join(&name)).expect("Stage catalog file");
            }
        }
        assert!(
            staged_catalog.join(own_checks).is_dir(),
            "Builtin checks for the target OS are missing"
        );
        for foreign in CHECK_DIRS.iter().filter(|dir| **dir != own_checks) {
            let foreign = staged_catalog.join(foreign);
            if fs::symlink_metadata(&foreign)
                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
            {
                fs::remove_dir_all(&foreign).expect("Remove other-OS staged checks");
            }
        }
        let obsolete_catalog = target.join("catalog/requirements.json");
        match fs::symlink_metadata(&obsolete_catalog) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(&obsolete_catalog)
                    .expect("Remove obsolete static requirements catalog");
            }
            Ok(_) => panic!("Obsolete requirements catalog path is not a file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("Inspect obsolete requirements catalog: {error}"),
        }
        let obsolete_tools = target.join("tools");
        match fs::symlink_metadata(&obsolete_tools) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir_all(&obsolete_tools).expect("Remove obsolete duplicated tools tree");
            }
            Ok(_) => fs::remove_file(&obsolete_tools).expect("Remove obsolete tools artifact"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("Inspect obsolete tools tree: {error}"),
        }
        if web.is_dir() {
            copy_tree(&web, &target.join("web"));
        }
        // The legacy SEC-011 adapter is no longer shipped; drop stale staged copies.
        let obsolete_adapters = target.join("checks");
        if fs::symlink_metadata(&obsolete_adapters)
            .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
        {
            fs::remove_dir_all(&obsolete_adapters)
                .expect("Remove obsolete legacy adapter directory");
        }
    }
}
