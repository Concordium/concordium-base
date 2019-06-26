// -*- mode: rust; -*-
//
// This file is part of concordium_crypto
// Copyright (c) 2019 -
// See LICENSE for licensing information.
//
// Authors:
// - bm@concordium.com

// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.
#![allow(non_snake_case)]


use core::fmt::{self, Display};
// use pairing::{GroupDecodingError, PrimeFieldDecodingError};

/// Internal errors.  

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum InternalError {
    // GDecodingError(GroupDecodingError),
    // FDecodingError(PrimeFieldDecodingError),
    CurveDecodingError,
    FieldDecodingError,
    CommitmentKeyLengthError,
    ValueVecLengthError,
    CommitmentLengthError,
    KeyValueLengthMismatch,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            // InternalError::GDecodingError(ref p) => write!(f, "{}", p),
            // InternalError::FDecodingError(ref p) => write!(f, "{}", p),
            InternalError::CurveDecodingError => write!(f, "Not on Curve"),
            InternalError::FieldDecodingError => write!(f, "Not a Field element"),
            InternalError::CommitmentKeyLengthError => {
                write!(f, "wrong length of commitment key bytes")
            }
            InternalError::CommitmentLengthError => write!(f, "wrong length of commitment bytes "),
            InternalError::ValueVecLengthError => write!(f, "wrong length of value vec bytes "),
            InternalError::KeyValueLengthMismatch => {
                write!(f, "wrong value vec length or key length or both")
            }
        }
    }
}

impl ::failure::Fail for InternalError {}

/// Errors which may occur druing execution
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decompressing to a scalar or group element,

#[derive(Debug)]
pub struct CommitmentError(pub(crate) InternalError);

impl Display for CommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl ::failure::Fail for CommitmentError {
    fn cause(&self) -> Option<&dyn (::failure::Fail)> { Some(&self.0) }
}
