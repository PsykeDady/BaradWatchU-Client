//! Fedora-specific RPM/DNF5 inspection; shared storage aliases preserve the CP2 library API.
mod updates;
pub use super::linux::{
    storage::{encryption, encryption_with_topology},
    topology,
};
pub use updates::updates;
