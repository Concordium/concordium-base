// -*- mode: rust; -*-
//
// This file is part of concordium_crypto
// Copyright (c) 2019 -
// See LICENSE for licensing information.
//
// Authors:
// - bm@concordium.com

//! Errors which may occur when parsing keys and/or proofs to or from wire
//! formats.

// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.
#![allow(non_snake_case)]

use core::fmt::{self, Display};

/// Internal errors.  Most application-level developers will likely not
/// need to pay any attention to these.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
// TODO : Remove when done prototyping
#[allow(dead_code)]
pub(crate) enum InternalError {
    PointDecompression,
    ScalarFormat,
    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass a string specifying the `name` of the type which is
    /// returning the error, and the `length` in bytes which its constructor
    /// expects.
    BytesLength {
        name:   &'static str,
        length: usize,
    },
    /// The verification equation wasn't satisfied
    Verify,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InternalError::PointDecompression => write!(f, "Cannot decompress Edwards point"),
            InternalError::ScalarFormat => write!(f, "Cannot use scalar with high-bit set"),
            InternalError::BytesLength { name: n, length: l } => {
                write!(f, "{} must be {} bytes in length", n, l)
            }
            InternalError::Verify => write!(f, "Verification equation was not satisfied"),
        }
    }
}

impl ::failure::Fail for InternalError {}

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
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub struct ProofError(pub(crate) InternalError);

impl Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl ::failure::Fail for ProofError {
    fn cause(&self) -> Option<&dyn (::failure::Fail)> { Some(&self.0) }
}
