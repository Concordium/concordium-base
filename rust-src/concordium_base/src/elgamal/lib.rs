//! Implementation of elgamal public key encryption and decryption over a Curve.

mod cipher;
mod elgamal;
mod errors;
mod message;
mod public;
mod secret;

pub use crate::{cipher::*, elgamal::*, message::*, public::*, secret::*};

#[macro_use]
extern crate crypto_common_derive;
