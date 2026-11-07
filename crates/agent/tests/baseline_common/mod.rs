#![allow(dead_code)]
use baradwatchu_agent::{
    audit::Reason,
    platform::{
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        linux::{
            baseline::{
                files::{Files, Node, NodeKind},
                screen_lock::SessionContext,
            },
            environment::{Environment, Kind},
        },
    },
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
};
pub fn host() -> Environment {
    Environment {
        kind: Kind::NativeHost,
        reason: "fixture",
        probe_error: None,
    }
}
pub fn node(kind: NodeKind) -> Node {
    Node {
        kind,
        major: 10,
        minor: 224,
        readable: true,
        owner: 0,
        size: 32,
        modified_ns: Some(1),
        inode: 1,
    }
}
#[derive(Default)]
pub struct Fs {
    pub reads: BTreeMap<String, Result<Option<Vec<u8>>, ProbeError>>,
    pub nodes: BTreeMap<String, Result<Option<Node>, ProbeError>>,
    pub directories: BTreeMap<String, Result<Option<Vec<String>>, ProbeError>>,
    pub calls: RefCell<Vec<String>>,
}
impl Fs {
    pub fn directory(&mut self, p: &str) {
        self.nodes
            .insert(p.into(), Ok(Some(node(NodeKind::Directory))));
    }
    pub fn text(&mut self, p: &str, s: &str) {
        self.reads.insert(p.into(), Ok(Some(s.as_bytes().to_vec())));
        self.nodes
            .insert(p.into(), Ok(Some(node(NodeKind::Regular))));
    }
}
impl Files for Fs {
    fn read(&self, p: &str, limit: usize) -> Result<Option<Vec<u8>>, ProbeError> {
        self.calls.borrow_mut().push(p.into());
        let bytes = self.reads.get(p).cloned().unwrap_or(Ok(None))?;
        if bytes.as_ref().is_some_and(|b| b.len() > limit) {
            return Err(ProbeError::new(Reason::OutputLimit, "fixture"));
        }
        Ok(bytes)
    }
    fn info(&self, p: &str) -> Result<Option<Node>, ProbeError> {
        self.calls.borrow_mut().push(p.into());
        self.nodes.get(p).cloned().unwrap_or(Ok(None))
    }
    fn entries(&self, p: &str) -> Result<Option<Vec<String>>, ProbeError> {
        self.calls.borrow_mut().push(p.into());
        self.directories.get(p).cloned().unwrap_or(Ok(None))
    }
}
pub struct Runner {
    pub outputs: RefCell<VecDeque<Result<CommandOutput, ProbeError>>>,
    pub calls: RefCell<Vec<CommandSpec>>,
}
impl Runner {
    pub fn new(outputs: Vec<Result<CommandOutput, ProbeError>>) -> Self {
        Self {
            outputs: RefCell::new(outputs.into()),
            calls: RefCell::new(vec![]),
        }
    }
}
impl CommandRunner for Runner {
    fn run(&self, s: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        self.calls.borrow_mut().push(s.clone());
        self.outputs
            .borrow_mut()
            .pop_front()
            .expect("unexpected baseline command")
    }
}
pub fn out(s: &str) -> Result<CommandOutput, ProbeError> {
    Ok(CommandOutput {
        code: Some(0),
        stdout: s.into(),
        stderr: String::new(),
    })
}
pub fn json(data: serde_json::Value) -> Result<CommandOutput, ProbeError> {
    let first = data.as_array().and_then(|a| a.first());
    let signature = match first {
        Some(v) if v.is_boolean() => "b",
        Some(v) if v.is_number() => "u",
        Some(v) if v.is_object() => "v",
        _ => "a(susso)",
    };
    out(&serde_json::json!({"type":signature,"data":data}).to_string())
}
pub fn user() -> SessionContext {
    SessionContext {
        uid: 1000,
        home: Some("/home/fixture".into()),
        config_home: None,
        config_dirs: None,
        kde_version: Some("6".into()),
    }
}
pub fn schema() -> String {
    let mut text = String::from("<kcfg><group name=\"Daemon\">");
    for (k, v) in [
        ("Autolock", "true"),
        ("Timeout", "5"),
        ("Lock", "true"),
        ("LockGrace", "5"),
        ("RequirePassword", "true"),
        ("LockOnResume", "true"),
    ] {
        text += &format!("<entry key=\"{k}\"><default>{v}</default></entry>")
    }
    text + "</group></kcfg>"
}
pub fn screen_files() -> Fs {
    let mut fs = Fs::default();
    let mut home = node(NodeKind::Directory);
    home.owner = 1000;
    fs.nodes.insert("/home/fixture".into(), Ok(Some(home)));
    let mut socket = node(NodeKind::Socket);
    socket.owner = 1000;
    fs.nodes
        .insert("/run/user/1000/bus".into(), Ok(Some(socket)));
    fs.text(
        "/usr/share/config.kcfg/kscreenlockersettings.kcfg",
        &schema(),
    );
    fs
}
pub fn sessions(uid: u32) -> serde_json::Value {
    serde_json::json!([[[
        "1",
        uid,
        "private-user",
        "seat0",
        "/org/freedesktop/login1/session/_31"
    ]]])
}
pub fn screen_commands() -> Vec<Result<CommandOutput, ProbeError>> {
    vec![
        json(serde_json::json!([true])),
        json(sessions(1000)),
        json(serde_json::json!([{"type":"s","data":"wayland"}])),
        json(serde_json::json!([{"type":"s","data":"KDE"}])),
        json(serde_json::json!([{"type":"s","data":"user"}])),
        json(serde_json::json!([{"type":"b","data":false}])),
        json(serde_json::json!([true])),
        json(serde_json::json!([1000])),
        json(serde_json::json!([false])),
        out("true\n"),
        out("4\n"),
        out("true\n"),
        out("5\n"),
        out("true\n"),
        out("true\n"),
    ]
}
pub fn services(active: &[&str]) -> String {
    ["firewalld", "nftables", "ufw", "iptables", "ip6tables"]
        .iter()
        .map(|n| {
            format!(
                "Id={n}.service\nLoadState={}\nActiveState={}\nSubState={}\n",
                if active.contains(n) {
                    "loaded"
                } else {
                    "not-found"
                },
                if active.contains(n) {
                    "active"
                } else {
                    "inactive"
                },
                if active.contains(n) {
                    "running"
                } else {
                    "dead"
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub const NFT_DROP: &str = include_str!("../fixtures/nft-input-drop.json");
pub const NFT_EMPTY: &str = r#"{"nftables":[]}"#;
pub const IPT_DROP: &str =
    "*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n";
pub const IPT_ACCEPT: &str =
    "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n";
