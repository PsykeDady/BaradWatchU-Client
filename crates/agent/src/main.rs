use baradwatchu_agent::platform;

fn main() {
    println!(
        "BaradWatchU agent bootstrap ({})",
        platform::current_platform()
    );
}
