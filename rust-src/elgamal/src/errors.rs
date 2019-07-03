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

use curve_arithmetic::curve_arithmetic as carith;

/// Internal errors.  

#[derive(Debug)]
pub(crate) enum InternalError {
    FieldDecoding(carith::FieldDecodingError),
    GroupDecoding(carith::CurveDecodingError),
    PublicKeyLength,
    MessageLength,
    CipherLength,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InternalError::GroupDecoding(ref e) => write!(f, "Group decoding error {:?}", e),
            InternalError::FieldDecoding(ref e) => write!(f, "Field decoding error {:?}", e),
            InternalError::PublicKeyLength => write!(f, "Wrong PublicKey length"),
            InternalError::MessageLength => write!(f, "Wrong message length"),
            InternalError::CipherLength => write!(f, "Wrong cipher length"),
        }
    }
}

impl ::failure::Fail for InternalError {}

/// Errors which may occur while processing keys, encryption and decryptoin.
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decoding to a scalar,
///
/// * A problem  decoding to a group element

#[derive(Debug)]
pub struct ElgamalError(pub(crate) InternalError);

impl From<carith::FieldDecodingError> for ElgamalError {
    fn from(err: carith::FieldDecodingError) -> Self {
        ElgamalError(InternalError::FieldDecoding(err))
    }
}

impl From<carith::CurveDecodingError> for ElgamalError {
    fn from(err: carith::CurveDecodingError) -> Self {
        ElgamalError(InternalError::GroupDecoding(err))
    }
}

impl Display for ElgamalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl ::failure::Fail for ElgamalError {
    fn cause(&self) -> Option<&dyn (::failure::Fail)> { Some(&self.0) }
}
