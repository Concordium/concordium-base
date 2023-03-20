//! This module and its submodules implement the Concordium identity layer,
//! providing the core functionality for all entities involved (users, identity
//! providers, and the chain).
pub mod account_holder;
pub mod anonymity_revoker;
pub mod chain;
pub mod constants;
#[cfg(feature = "ffi")]
mod ffi;
pub mod id_proof_types;
pub mod id_prover;
pub mod id_verifier;
pub mod identity_provider;
pub mod secret_sharing;
pub mod sigma_protocols;
pub mod types;
pub mod utils;

/// Re-export of Pedersen commitments functionality.
pub use crate::pedersen_commitment;

/// Re-export of curve arithmetic.
pub use crate::curve_arithmetic;

/// Re-export of Elgamal encryption.
pub use crate::elgamal;

/// Re-export of bulletproofs.
pub use crate::bulletproofs::range_proof;

/// Re-export the PRF key generation functionality.
pub use crate::dodis_yampolskiy_prf;

/// Re-export the Pointcheval-Sanders signature scheme used by identity
/// providers.
pub use crate::ps_sig;

#[cfg(any(test, feature = "internal-test-helpers"))]
#[doc(hidden)]
pub mod test;
