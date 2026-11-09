//! BaradWatchU Client: local requirement catalog, runner, CLI and loopback dashboard.

pub mod cli;
mod configuration;
pub mod consent;
pub mod dashboard;
pub mod events;
pub mod messages {
    pub use baradwatchu_messages::*;
}
mod history;
mod pdf;
pub mod requirements;
