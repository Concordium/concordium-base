//! Implementation of bulletproofs in the scope needed by Concordium.
//!
//! In particular this means
//!  * range proofs for 64-bit unsigned integers.
//!  * set membership proofs for scalars of curve `C`.
pub mod inner_product_proof;
pub mod range_proof;
pub mod set_membership_proof;
pub mod set_non_membership_proof;
pub mod utils;
