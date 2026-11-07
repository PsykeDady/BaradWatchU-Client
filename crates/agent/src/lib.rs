//! Standalone read-only audit; service, policy and transport remain future boundaries.

pub mod adapters;
pub mod audit;
pub mod check_port;
pub mod checks;
pub mod cli;
pub mod communication;
pub mod dashboard;
pub mod local_config;
pub mod observation;
pub mod platform;
pub mod policy;
pub mod requirements;
pub mod service;
pub mod workstation;
