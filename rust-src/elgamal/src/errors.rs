// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.
#![allow(non_snake_case)]

use thiserror::Error;
/// Internal errors.  

#[derive(Error, Debug)]
#[allow(dead_code)]
pub(crate) enum InternalError {
    #[error("wrong publickey length")]
    PublicKey,
    #[error("wrong message length")]
    Message,
    #[error("wrong cipher length")]
    Cipher,
}

/// Errors which may occur while processing keys, encryption and decryptoin.
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decoding to a scalar,
///
/// * A problem  decoding to a group element

#[derive(Error, Debug)]
#[error("{0}")]
pub struct ElgamalError(pub(crate) InternalError);
