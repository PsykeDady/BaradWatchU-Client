//! End-to-end CLI checks for the local identity and trust store (isolated XDG folders).
use std::process::{Command, Stdio};

fn agent(root: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_baradwatchu-agent"));
    command
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("LC_ALL", "en_US.UTF-8")
        .stdin(Stdio::null());
    command
}

fn root(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "bwu-identity-cli-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    // Pin the language: expectations below are in English.
    std::fs::create_dir_all(path.join("config/baradwatchu")).unwrap();
    std::fs::write(
        path.join("config/baradwatchu/language.json"),
        r#"{"schemaVersion":"baradwatchu.language.v1","language":"english"}"#,
    )
    .unwrap();
    path
}

#[test]
fn identity_lifecycle_through_the_binary() {
    let root = root("lifecycle");
    let identity_dir = root.join("state/baradwatchu/identity");

    // Absent by default; local commands keep working and never create keys.
    let output = agent(&root).args(["identity", "show"]).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("not configured"));
    let output = agent(&root).args(["status"]).output().unwrap();
    assert!(output.status.code().is_some());
    let output = agent(&root).args(["history", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !identity_dir.exists(),
        "local commands created identity data"
    );

    // No terminal and no --yes: refused with the mandatory warning on stderr.
    let output = agent(&root)
        .args(["identity", "generate"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BaradWatchU Server"), "{stderr}");
    assert!(stderr.contains("public key"), "{stderr}");
    assert!(!identity_dir.join("state.json").exists());

    let output = agent(&root)
        .args(["identity", "generate", "--yes"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let generated = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(generated.contains("Device ID: BWU-"));

    let export = agent(&root).args(["identity", "export"]).output().unwrap();
    assert_eq!(export.status.code(), Some(0));
    let document: serde_json::Value = serde_json::from_slice(&export.stdout).unwrap();
    assert_eq!(document["schemaVersion"], "baradwatchu.public-identity.v1");
    assert_eq!(document["role"], "client");

    // The private seed never appears in any output.
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(identity_dir.join("state.json")).unwrap()).unwrap();
    let key_dir = identity_dir.join(state["identity"].as_str().unwrap());
    let private: serde_json::Value =
        serde_json::from_slice(&std::fs::read(key_dir.join("private.key")).unwrap()).unwrap();
    let seed = private["seed"].as_str().unwrap();
    let show = agent(&root)
        .args(["identity", "show", "--json"])
        .output()
        .unwrap();
    for bytes in [
        &output.stdout,
        &output.stderr,
        &export.stdout,
        &show.stdout,
        &show.stderr,
    ] {
        assert!(!String::from_utf8_lossy(bytes).contains(seed));
    }

    // Second generation refused; reset without terminal refused; with --yes it rotates.
    assert_eq!(
        agent(&root)
            .args(["identity", "generate", "--yes"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        agent(&root)
            .args(["identity", "reset"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    let reset = agent(&root)
        .args(["identity", "reset", "--yes"])
        .output()
        .unwrap();
    assert_eq!(reset.status.code(), Some(0));
    let after = agent(&root).args(["identity", "export"]).output().unwrap();
    let after: serde_json::Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_ne!(after["publicKey"], document["publicKey"]);
    assert!(!key_dir.exists());

    // Usage errors and help.
    assert_eq!(
        agent(&root)
            .args(["identity"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        agent(&root)
            .args(["trust", "nope"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    let help = agent(&root).args(["trust", "--help"]).output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("trust import FILE"));
    let help = agent(&root).args(["--help"]).output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("identity generate"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn trust_import_from_a_local_file_needs_the_verified_fingerprint() {
    let root = root("trust");
    // A Server key file as the future Server will export it (role "server").
    let client = agent(&root)
        .args(["identity", "generate", "--yes"])
        .output()
        .unwrap();
    assert_eq!(client.status.code(), Some(0));
    let other = root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::create_dir_all(other.join("config/baradwatchu")).unwrap();
    agent(&other)
        .args(["identity", "generate", "--yes"])
        .output()
        .unwrap();
    let export = agent(&other).args(["identity", "export"]).output().unwrap();
    let mut document: serde_json::Value = serde_json::from_slice(&export.stdout).unwrap();
    let fingerprint = document["fingerprint"].as_str().unwrap().to_owned();
    // A Client export is refused as a Server key.
    let client_file = root.join("client.json");
    std::fs::write(&client_file, &export.stdout).unwrap();
    let output = agent(&root)
        .args([
            "trust",
            "import",
            client_file.to_str().unwrap(),
            "--fingerprint",
            &fingerprint,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    document["role"] = "server".into();
    document["name"] = "Server Test".into();
    document.as_object_mut().unwrap().remove("id");
    let file = root.join("server.json");
    std::fs::write(&file, serde_json::to_vec(&document).unwrap()).unwrap();
    let path = file.to_str().unwrap();

    let output = agent(&root)
        .args(["trust", "import", path])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "no terminal, no --fingerprint"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains(&fingerprint));
    let output = agent(&root)
        .args(["trust", "import", path, "--fingerprint", &"0".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let output = agent(&root)
        .args(["trust", "import", path, "--fingerprint", &fingerprint])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let list = agent(&root)
        .args(["trust", "list", "--json"])
        .output()
        .unwrap();
    let servers: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let id = servers[0]["serverId"].as_str().unwrap().to_owned();
    assert_eq!(servers[0]["status"], "TRUSTED");
    let show = agent(&root).args(["trust", "show", &id]).output().unwrap();
    assert!(String::from_utf8_lossy(&show.stdout).contains("Server Test"));

    assert_eq!(
        agent(&root)
            .args(["trust", "revoke", &id])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        agent(&root)
            .args(["trust", "revoke", &id, "--yes"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let identity_before = agent(&root)
        .args(["identity", "export"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        agent(&root)
            .args(["trust", "clear", "--yes"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let list = agent(&root)
        .args(["trust", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&list.stdout).trim(), "[]");
    let identity_after = agent(&root)
        .args(["identity", "export"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        identity_before, identity_after,
        "trust clear changed the identity"
    );
    std::fs::remove_dir_all(root).unwrap();
}
