//! An implementation of the Pointcheval-Sanders signature scheme <https://eprint.iacr.org/2015/525>
mod errors;
mod known_message;
mod public;
mod secret;
mod signature;
mod unknown_message;

pub use known_message::*;
pub use public::*;
pub use secret::*;
pub use signature::*;
pub use unknown_message::*;

#[macro_use]
extern crate crypto_common_derive;
