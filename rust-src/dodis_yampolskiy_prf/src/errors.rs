// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.

use thiserror::Error;

/// Internal errors.  

#[derive(Debug, Error)]
pub(crate) enum InternalError {
    #[error("Division by zero.")]
    DivisionByZero,
}

/// Errors which may occur while processing proofs and keys.
///
/// This error may arise due to:
///
/// * A problem with the format of `s`, a scalar,

#[derive(Debug, Error)]
#[error(transparent)] // Forwards the Display and Source implementations of the wrapped InternalError
pub struct PrfError(pub(crate) InternalError);
