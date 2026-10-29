use baradwatchu_agent::platform;

fn main() {
    if let Err(error) = handle_cli() {
        eprintln!("{error}");
        std::process::exit(2);
    }
    println!(
        "BaradWatchU agent bootstrap ({})",
        platform::current_platform()
    );
}

fn handle_cli() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok(()),
        [flag] if flag == "--version" || flag == "-V" => {
            println!("BaradWatchU Client {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "BaradWatchU Client {}\n\nUsage: baradwatchu-agent [OPTIONS]\n\nOptions:\n  -h, --help       Show this help and exit\n  -V, --version    Show product version and exit\n\nThis bootstrap identifies the current platform and exits. Audit commands,\nservice management and server communication are planned but not implemented.",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(0);
        }
        _ => Err("invalid arguments; use --help for usage".to_owned()),
    }
}
