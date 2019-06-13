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
use curve_arithmetic::curve_arithmetic::*;

/// Internal errors.  

#[derive(Debug)]
pub(crate) enum InternalError {
    CurveDecodingError,
    FieldDecodingError,
    SignatureKeyLengthError,
    SignatureLengthError,
    SecretKeyLengthError,
    PublicKeyLengthError,
    MessageVecLengthError,
    MessageLengthError,
    KeyMessageLengthMismatch,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InternalError::CurveDecodingError => write!(f, "Not on Curve"),
            InternalError::SecretKeyLengthError => write!(f, "wrong length of secret key"),
            InternalError::PublicKeyLengthError => write!(f, "wrong length of public key"),
            InternalError::FieldDecodingError => write!(f, "Not a Field element"),
            InternalError::SignatureLengthError => write!(f, "wrong length of signature"),
            InternalError::MessageLengthError => write!(f, "wrong length of message"),
            InternalError::SignatureKeyLengthError => {
                write!(f, "wrong length of signature key bytes")
            }
            InternalError::SignatureLengthError => write!(f, "wrong length of signature bytes "),
            InternalError::MessageVecLengthError => write!(f, "wrong length of message vec bytes "),
            InternalError::KeyMessageLengthMismatch => {
                write!(f, "wrong message vec length or key length or both")
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
pub struct SignatureError(pub(crate) InternalError);

impl Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl ::failure::Fail for SignatureError {
    fn cause(&self) -> Option<&dyn (::failure::Fail)> { Some(&self.0) }
}
