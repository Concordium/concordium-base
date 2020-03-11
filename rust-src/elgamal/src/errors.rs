// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.
#![allow(non_snake_case)]

use core::fmt::{self, Display};
/// Internal errors.  

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum InternalError {
    PublicKey,
    Message,
    Cipher,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InternalError::PublicKey => write!(f, "Wrong PublicKey length"),
            InternalError::Message => write!(f, "Wrong message length"),
            InternalError::Cipher => write!(f, "Wrong cipher length"),
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

impl Display for ElgamalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl ::failure::Fail for ElgamalError {
    fn cause(&self) -> Option<&dyn (::failure::Fail)> { Some(&self.0) }
}
