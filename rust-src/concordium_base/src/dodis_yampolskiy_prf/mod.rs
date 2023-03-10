//! Implementation of the [Dodis-Yampolskiy](https://eprint.iacr.org/2004/310.pdf) PRF function.
//! This is used when creating credentials to get a random-looking credential
//! registration ID.
mod errors;
mod secret;

pub use secret::*;
