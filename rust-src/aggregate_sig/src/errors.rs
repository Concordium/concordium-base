use std::{error::Error, fmt};

#[derive(Debug)]
pub(crate) enum InternalError {
    CurveDecodingError(curve_arithmetic::CurveDecodingError),
    FieldDecodingError(curve_arithmetic::FieldDecodingError),
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalError::CurveDecodingError(err) => write!(f, "Group decoding error {:?}", err),
            InternalError::FieldDecodingError(err) => write!(f, "Field decoding error {:?}", err),
        }
    }
}

impl Error for InternalError {}

#[derive(Debug)]
pub struct AggregateSigError(pub(crate) InternalError);

impl From<curve_arithmetic::CurveDecodingError> for AggregateSigError {
    fn from(err: curve_arithmetic::CurveDecodingError) -> Self {
        AggregateSigError(InternalError::CurveDecodingError(err))
    }
}

impl From<curve_arithmetic::FieldDecodingError> for AggregateSigError {
    fn from(err: curve_arithmetic::FieldDecodingError) -> Self {
        AggregateSigError(InternalError::FieldDecodingError(err))
    }
}

impl fmt::Display for AggregateSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl Error for AggregateSigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.0) }
}
