//! Errors which may occur when parsing keys and/or proofs to or from wire
//! formats.

use thiserror::Error;

/// Internal errors.  Most application-level developers will likely not
/// need to pay any attention to these.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Error)]
pub(crate) enum InternalError {
    #[error("Cannot decompress Edwards point.")]
    PointDecompression,
    #[error("Cannot use scalar with high-bit set.")]
    ScalarFormat,
    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass a string specifying the `name` of the type which is
    /// returning the error, and the `length` in bytes which its constructor
    /// expects.
    #[error("{name} must be {length} bytes in length.")]
    BytesLength { name: &'static str, length: usize },
    /// The verification equation wasn't satisfied
    #[error("Verification equation was not satisfied.")]
    Verify,
}

/// Errors which may occur while processing proofs and keypairs.
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decompressing to a curve point, from `proof`, or `PublicKey`.
///
/// * A problem with the format of `s`, a scalar, in the `Signature`.  This is
///   only raised if the high-bit of the scalar was set.  (Scalars must only be
///   constructed from 255-bit integers.)
///
/// * Failure of a proof to satisfy the verification equation.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Error)]
#[error("ProofError: {0}")]
pub struct ProofError(pub(crate) InternalError);
