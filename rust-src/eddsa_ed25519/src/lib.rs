extern crate ed25519_dalek;
extern crate rand;
extern crate serde;

pub mod common;
pub mod dlog_ed25519;
mod eddsa_ed25519;

pub use crate::{dlog_ed25519::*, eddsa_ed25519::*};
