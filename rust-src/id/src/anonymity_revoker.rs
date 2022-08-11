//! Functionality needed by the anonymity revoker.
use crate::{secret_sharing::*, types::*};
use curve_arithmetic::*;
use elgamal::Message;

/// Reveal the `idCredPub` based on the given shares.
/// It is important to remember that this always succeeds in computing
/// something. It simply does polynomial interpolation. Whether the resulting
/// value is meaningful must be ensured by the caller, e.g., by making sure that
/// the threshold is compatible with the number of shares.
pub fn reveal_id_cred_pub<C: Curve>(shares: &[(ArIdentity, Message<C>)]) -> C {
    reveal_in_group(
        &shares
            .iter()
            .map(|(n, m)| (*n, m.value))
            .collect::<Vec<_>>(),
    )
}

/// Reveal the PRF key based on the given shares.
/// It is important to remember that this always succeeds in computing
/// something. It simply does polynomial interpolation. Whether the resulting
/// value is meaningful must be ensured by the caller, e.g., by making sure that
/// the threshold is compatible with the number of shares.
pub fn reveal_prf_key<C: Curve>(shares: &[(ArIdentity, Value<C>)]) -> C::Scalar { reveal(shares) }
