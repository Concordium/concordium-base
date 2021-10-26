#[macro_use]
extern crate itertools;

pub mod account_holder;
pub mod anonymity_revoker;
pub mod chain;
pub mod constants;
#[cfg(feature = "ffi")]
mod ffi;
pub mod id_prover;
pub mod id_verifier;
pub mod identity_provider;
pub mod secret_sharing;
pub mod sigma_protocols;
pub mod types;
pub mod utils;

/// Re-export of Pedersen commitments functionality.
pub use pedersen_scheme as pedersen_commitment;

/// Re-export of curve arithmetic.
pub use curve_arithmetic;

/// Re-export of Elgamal encryption.
pub use elgamal;

/// Re-export of bulletproofs.
pub use bulletproofs::range_proof;

#[macro_use]
extern crate crypto_common_derive;

#[cfg(any(test, feature = "test-helpers"))]
pub mod test;
