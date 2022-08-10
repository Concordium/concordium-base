//! A few helpers around the dalek ed25519 signature scheme.
mod dlog_ed25519;
mod eddsa_ed25519;

pub use crate::{dlog_ed25519::*, eddsa_ed25519::*};
