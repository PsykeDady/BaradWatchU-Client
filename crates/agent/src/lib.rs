//! BaradWatchU Client: local requirement catalog, runner, CLI and loopback dashboard.

pub mod cli;
mod configuration;
pub mod consent;
pub mod dashboard;
pub mod events;
pub mod identity;
mod ipc;
pub mod remote;
mod service;
pub mod messages {
    pub use baradwatchu_messages::*;
}
mod history;
mod pdf;
pub mod requirements;
