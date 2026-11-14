//! BaradWatchU Client: local requirement catalog, runner, CLI and loopback dashboard.

pub mod cli;
mod configuration;
pub mod consent;
mod cron;
pub mod dashboard;
pub mod elevation;
pub mod events;
pub mod identity;
mod ipc;
mod periodic;
mod policy;
pub mod remote;
mod service;
pub mod messages {
    pub use baradwatchu_messages::*;
}
mod history;
mod pdf;
pub mod requirements;
