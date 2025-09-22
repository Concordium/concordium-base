use crate::common::cbor::{
    value, CborDecoder, CborDeserialize, CborEncoder, CborMaybeKnown, CborSerializationResult,
    CborSerialize,
};

/// Type for forward-compatibility with the Concordium Node API.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Upward<A, R = ()> {
    /// New unknown variant, the structure is not known to the current version
    /// of this library. Consider updating the library if support is needed.
    Unknown(R),
    /// Known variant.
    Known(A),
}

impl<A, R> Upward<A, R> {
    pub fn known_or_else<E, F>(self, error: F) -> Result<A, E>
    where
        F: FnOnce(R) -> E,
    {
        match self {
            Upward::Unknown(residual) => Err(error(residual)),
            Upward::Known(output) => Ok(output),
        }
    }

    /// Maps an `Upward<A, R>` to `Upward<A, S>` by applying a function to
    /// the residual value in `Unknown`.
    pub fn map_unknown<S, F>(self, f: F) -> Upward<A, S>
    where
        F: FnOnce(R) -> S,
    {
        match self {
            Self::Known(x) => Upward::Known(x),
            Self::Unknown(r) => Upward::Unknown(f(r)),
        }
    }
}

/// Special case where the residual type is a CBOR value, so that CBOR can be deserialized
/// to an unknown variant in the case that the library version is behind.
pub type CborUpward<A> = Upward<A, value::Value>;

impl<T: CborSerialize> CborSerialize for CborUpward<T> {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        match self {
            Self::Unknown(value) => value.serialize(encoder),
            Self::Known(value) => value.serialize(encoder),
        }
    }
}

impl<T: CborDeserialize> CborDeserialize for CborUpward<T> {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        Ok(match T::deserialize_maybe_known(decoder)? {
            CborMaybeKnown::Unknown(r) => Self::Unknown(r),
            CborMaybeKnown::Known(val) => Self::Known(val),
        })
    }
}
