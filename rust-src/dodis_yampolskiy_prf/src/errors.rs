// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.

use core::fmt::{self, Display};

/// Internal errors.  

#[derive(Debug)]
pub(crate) enum InternalError {
    DivisionByZero,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InternalError::DivisionByZero => write!(f, "Division By Zero"),
        }
    }
}

impl ::failure::Fail for InternalError {}

/// Errors which may occur while processing proofs and keys.
///
/// This error may arise due to:
///
/// * A problem with the format of `s`, a scalar,

#[derive(Debug)]
pub struct PrfError(pub(crate) InternalError);

impl Display for PrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl ::failure::Fail for PrfError {
    fn cause(&self) -> Option<&dyn (::failure::Fail)> { Some(&self.0) }
}
