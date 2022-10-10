//! A few helpers around the dalek ed25519 signature scheme.
mod dlog_ed25519;
// this module only has FFI exports, so we don't need to re-export anything.
mod eddsa_ed25519;

pub use crate::dlog_ed25519::*;
