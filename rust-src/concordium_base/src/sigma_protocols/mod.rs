//! Implementations of sigma protocols needed by the identity layer of
//! Concordium.
pub mod aggregate_dlog;
pub mod com_enc_eq;
pub mod com_eq;
pub mod com_eq_different_groups;
pub mod com_eq_sig;
pub mod com_ineq;
pub mod com_lin;
pub mod com_mult;
pub mod common;
pub mod dlog;
pub mod enc_trans;
pub mod vcom_eq;

// the following two modules are only there for reference if we ever need them,
// they are not used.
mod dlogaggequal;
mod dlogeq;

#[cfg(test)]
pub mod sigma_test;
