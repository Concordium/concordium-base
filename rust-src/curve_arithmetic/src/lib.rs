//! Basic definitions of the curve and pairing abstractions, and implementations
//! of these abstractions for the curves used on Concordium.
mod bls12_381_g1hash;
mod bls12_381_g2hash;
mod bls12_381_instance;
mod curve_arithmetic;
pub use crate::curve_arithmetic::*;

pub mod secret_value;
pub use secret_value::{Secret, Value};

#[macro_use]
extern crate crypto_common_derive;
