//! Compiled protocol fixture only; NOT a real Secure Boot inspector or production registration.
use std::{
    env,
    io::{self, Write},
    thread,
    time::Duration,
};
fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("available");
    match mode {
        "timeout"=>thread::sleep(Duration::from_secs(5)),
        "malformed"=>print!("not json"),
        "exit"=>std::process::exit(9),
        "large"=>{let _=io::stdout().write_all(&vec![b'x';300000]);},
        "stderr"=>{let _=io::stderr().write_all(&vec![b'x';300000]);},
        "unknown"=>println!("{{\"schemaVersion\":\"baradwatchu.check-evidence.v1\",\"checkId\":\"SEC-013\",\"availability\":\"UNKNOWN\",\"data\":null}}"),
        _=>println!("{{\"schemaVersion\":\"baradwatchu.check-evidence.v1\",\"checkId\":\"SEC-013\",\"availability\":\"AVAILABLE\",\"data\":{{\"kind\":\"SECURE_BOOT\",\"values\":{{\"state\":\"ENABLED\",\"secureBoot\":true,\"setupMode\":false}}}}}}"),
    }
}
