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
    println!("cargo:rerun-if-changed=../../web/src");
    println!("cargo:rerun-if-changed=../../web/dist/client-status/browser");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let catalog = manifest.join("../../catalog");
    let web = manifest.join("../../web/dist/client-status/browser");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = out
        .ancestors()
        .nth(3)
        .expect("Cargo profile output directory");
    // Main binaries live in profile/, test executables in profile/deps/.
    // Only the target OS's builtin checks are staged: Linux `catalog/checks`, Windows
    // `catalog/checks-windows`. The hash manifest covers both and is staged as is.
    let windows = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let (own_checks, other_checks) = if windows {
        ("checks-windows", "checks")
    } else {
        ("checks", "checks-windows")
    };
    for prefix in [profile.parent().unwrap(), profile] {
        let target = prefix.join("share/baradwatchu-client");
        let staged_catalog = target.join("catalog");
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
            if name == other_checks {
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
        let foreign = staged_catalog.join(other_checks);
        if fs::symlink_metadata(&foreign).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
            fs::remove_dir_all(&foreign).expect("Remove other-OS staged checks");
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
