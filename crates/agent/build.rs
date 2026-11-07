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
    println!("cargo:rerun-if-changed=../../scripts/adapters/SEC-011.sh");
    println!("cargo:rerun-if-changed=../../catalog");
    println!("cargo:rerun-if-changed=../../tools");
    println!("cargo:rerun-if-changed=../../web/src");
    println!("cargo:rerun-if-changed=../../web/dist/client-status/browser");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join("../../scripts/adapters/SEC-011.sh");
    let catalog = manifest.join("../../catalog");
    let tools = manifest.join("../../tools");
    let web = manifest.join("../../web/dist/client-status/browser");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = out
        .ancestors()
        .nth(3)
        .expect("Cargo profile output directory");
    // Main binaries live in profile/, test executables in profile/deps/.
    for prefix in [profile.parent().unwrap(), profile] {
        let target = prefix.join("share/baradwatchu-client");
        copy_tree(&catalog, &target.join("catalog"));
        copy_tree(&tools, &target.join("tools"));
        if web.is_dir() {
            copy_tree(&web, &target.join("web"));
        }
        let adapter = target.join("checks/SEC-011.sh");
        fs::create_dir_all(adapter.parent().unwrap()).expect("Create adapter artifact directory");
        fs::copy(&source, &adapter).expect("Stage approved adapter artifact");
    }
}
