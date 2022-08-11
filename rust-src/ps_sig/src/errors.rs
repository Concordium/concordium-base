use thiserror::Error;

/// Internal errors.  

#[derive(Debug, Error)]
#[allow(dead_code)]
pub(crate) enum InternalError {
    #[error("Not on Curve.")]
    CurveDecodingError,
    #[error("Not a Field element.")]
    FieldDecodingError,
    #[error("wrong length of signature key bytes")]
    SignatureKeyLengthError,
    #[error("Wrong length of signature.")]
    SignatureLengthError,
    #[error("Wrong length of secret key.")]
    SecretKeyLengthError,
    #[error("Wrong length of public key.")]
    PublicKeyLengthError,
    #[error("Wrong length of message vec bytes.")]
    MessageVecLengthError,
    #[error("Wrong length of message.")]
    MessageLengthError,
    #[error("Wrong message vec length or key length or both.")]
    KeyMessageLengthMismatch,
}

/// Errors which may occur druing execution
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decompressing to a scalar or group element,

#[derive(Debug, Error)]
#[error("SignatureError: {0}")]
pub struct SignatureError(pub(crate) InternalError);
