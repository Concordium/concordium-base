//! Implementation of aggregate signatures specified in <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04>
mod aggregate_sig;

#[cfg(feature = "ffi")]
mod ffi;

pub use aggregate_sig::*;
