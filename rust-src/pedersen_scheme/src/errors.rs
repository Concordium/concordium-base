use thiserror::Error;

/// Internal errors.  

#[derive(Error, Debug)]
#[allow(dead_code)]
pub(crate) enum InternalError {
    // GDecodingError(GroupDecodingError),
    // FDecodingError(PrimeFieldDecodingError),
    #[error("Not on curve.")]
    CurveDecodingError,
    #[error("Not a field element.")]
    FieldDecodingError,
    #[error("Wrong length of commitment key bytes.")]
    CommitmentKeyLengthError,
    #[error("Wrong length of commitment bytes.")]
    ValueVecLengthError,
    #[error("Wrong length of value vec bytes.")]
    CommitmentLengthError,
    #[error("Wrong value vec length or key length or both.")]
    KeyValueLengthMismatch,
}

/// Errors which may occur during execution
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decompressing to a scalar or group element,

#[derive(Error, Debug)]
#[error("CommitmentError: {0}")]
pub struct CommitmentError(pub(crate) InternalError);
