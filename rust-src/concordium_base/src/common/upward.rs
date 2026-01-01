use crate::common::cbor::{
    value, CborDecoder, CborDeserialize, CborEncoder, CborMaybeKnown, CborSerializationResult,
    CborSerialize,
};
use std::any::type_name;

/// Type for forward-compatibility with the Concordium Node API.
///
/// Wraps enum types which are expected to be extended some future version of
/// the Concordium Node API allowing the current SDK version to handle when new
/// variants are introduced in the API, unknown to this version of the SDK.
/// This is also used for helper methods extracting deeply nested information.
///
/// # `serde` implementation (deprecated).
///
/// To ensure some level of backwards-compatibility this implements
/// [`serde::Serialize`] and [`serde::Deserialize`], but serializing
/// `Upward::Unknown` will produce a runtime error and deserializing can only
/// produce `Upward::Known`.
/// The serde implementation should be considered deprecated and might be
/// removed in a future version.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Upward<A, R = ()> {
    /// New unknown variant, the structure is not known to the current version
    /// of this library. Consider updating the library if support is needed.
    ///
    /// For protocols that support decoding unknown data, the residual value is
    /// a representation of unknown data (represented by a dynamic data type).
    /// This is the case for CBOR e.g., but not possible for protobuf that is
    /// not self-descriptive.
    Unknown(R),
    /// Known variant.
    Known(A),
}

impl<A, R> Upward<A, R> {
    /// Returns the contained [`Upward::Known`] value, consuming the `self`
    /// value.
    ///
    /// # Panics
    ///
    /// Panics if the self value equals [`Upward::Unknown`].
    pub fn unwrap(self) -> A {
        match self {
            Self::Known(value) => value,
            Self::Unknown(_) => panic!(
                "called `Upward::<{}>::unwrap()` on an `Unknown` value",
                type_name::<A>()
            ),
        }
    }

    /// Transforms `Upward<T>` into a [`Option<T>`] where [`Option::Some`]
    /// represents [`Upward::Known`] and [`Option::None`] represents
    /// [`Upward::Unknown`].
    pub fn known(self) -> Option<A> {
        Option::from(self)
    }

    /// Borrow `Upward<T>` aa [`Option<&T>`] where [`Option::Some`]
    /// represents [`Upward::Known`] and [`Option::None`] represents
    /// [`Upward::Unknown`].
    pub fn as_known(&self) -> Option<&A> {
        Option::from(self.as_ref_with_residual())
    }

    /// Require the data to be known, converting it from `Upward<A>` to
    /// `Result<A, UnknownDataError>`.
    ///
    /// This is effectively opt out of forward-compatibility, forcing the
    /// library to be up to date with the node version.
    pub fn known_or_err(self) -> Result<A, UnknownDataError> {
        self.known_or(UnknownDataError {
            type_name: type_name::<A>(),
        })
    }

    /// Transforms the `Upward<T>` into a [`Result<T, E>`], mapping
    /// [`Known(v)`] to [`Ok(v)`] and [`Upward::Unknown`] to [`Err(err)`].
    ///
    /// Arguments passed to `known_or` are eagerly evaluated; if you are passing
    /// the result of a function call, it is recommended to use
    /// [`known_or_else`], which is lazily evaluated.
    ///
    /// [`Ok(v)`]: Ok
    /// [`Err(err)`]: Err
    /// [`Known(v)`]: Upward::Known
    /// [`known_or_else`]: Upward::known_or_else
    pub fn known_or<E>(self, error: E) -> Result<A, E> {
        Option::from(self).ok_or(error)
    }

    /// Transforms the `Upward<T>` into a [`Result<T, E>`], mapping
    /// [`Known(v)`] to [`Ok(v)`] and [`Upward::Unknown`] to [`Err(err())`].
    ///
    /// [`Ok(v)`]: Ok
    /// [`Err(err())`]: Err
    /// [`Known(v)`]: Upward::Known
    pub fn known_or_else<E, F>(self, error: F) -> Result<A, E>
    where
        F: FnOnce(R) -> E,
    {
        match self {
            Upward::Unknown(residual) => Err(error(residual)),
            Upward::Known(output) => Ok(output),
        }
    }

    /// Returns `true` if the Upward is a [`Upward::Known`] and the value inside
    /// of it matches a predicate.
    pub fn is_known_and(self, f: impl FnOnce(A) -> bool) -> bool {
        Option::from(self).is_some_and(f)
    }

    /// Maps an `Upward<A>` to `Upward<U>` by applying a function to a contained
    /// value (if `Known`) or returns `Unknown` (if `Unknown`).
    pub fn map<U, F>(self, f: F) -> Upward<U, R>
    where
        F: FnOnce(A) -> U,
    {
        match self {
            Self::Known(x) => Upward::Known(f(x)),
            Self::Unknown(r) => Upward::Unknown(r),
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

    /// Returns the provided default result (if [`Upward::Unknown`]),
    /// or applies a function to the contained value (if [`Upward::Known`]).
    ///
    /// Arguments passed to `map_or` are eagerly evaluated; if you are passing
    /// the result of a function call, it is recommended to use [`map_or_else`],
    /// which is lazily evaluated.
    ///
    /// [`map_or_else`]: Upward::map_or_else
    #[must_use = "if you don't need the returned value, use `if let` instead"]
    pub fn map_or<U, F>(self, default: U, f: F) -> U
    where
        F: FnOnce(A) -> U,
    {
        match self {
            Upward::Known(a) => f(a),
            Upward::Unknown(_) => default,
        }
    }

    /// Computes a default function result (if [`Upward::Unknown`]), or
    /// applies a different function to the contained value (if
    /// [`Upward::Known`]).
    pub fn map_or_else<U, D, F>(self, default: D, f: F) -> U
    where
        D: FnOnce() -> U,
        F: FnOnce(A) -> U,
    {
        match self {
            Upward::Known(t) => f(t),
            Upward::Unknown(_) => default(),
        }
    }

    /// Converts from `&Upward<A, R>` to `Upward<&A, &R>`.
    pub const fn as_ref_with_residual(&self) -> Upward<&A, &R> {
        match *self {
            Self::Known(ref x) => Upward::Known(x),
            Self::Unknown(ref r) => Upward::Unknown(r),
        }
    }

    /// Returns [`Upward::Unknown`] if the option is [`Upward::Unknown`],
    /// otherwise calls `f` with the wrapped value and returns the result.
    pub fn and_then<U, F>(self, f: F) -> Upward<U, R>
    where
        F: FnOnce(A) -> Upward<U, R>,
    {
        match self {
            Upward::Unknown(r) => Upward::Unknown(r),
            Upward::Known(x) => f(x),
        }
    }
}

/// Special case where the residual type is a CBOR value, so that CBOR can be deserialized
/// to an unknown variant in the case that the library version is behind.
pub type CborUpward<A> = Upward<A, value::Value>;

impl<T: CborSerialize> CborSerialize for CborUpward<T> {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
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

impl<A> Upward<A> {
    /// Converts from `&Upward<A>` to `Upward<&A>`.
    pub const fn as_ref(&self) -> Upward<&A> {
        match *self {
            Self::Known(ref x) => Upward::Known(x),
            Self::Unknown(_) => Upward::Unknown(()),
        }
    }
}

impl<A, R, E> Upward<Result<A, E>, R> {
    /// Transposes an `Upward` of a [`Result`] into a [`Result`] of an `Upward`.
    pub fn transpose(self) -> Result<Upward<A, R>, E> {
        match self {
            Upward::Known(Ok(x)) => Ok(Upward::Known(x)),
            Upward::Known(Err(e)) => Err(e),
            Upward::Unknown(r) => Ok(Upward::Unknown(r)),
        }
    }
}

impl<A> From<Option<A>> for Upward<A> {
    fn from(value: Option<A>) -> Self {
        if let Some(n) = value {
            Self::Known(n)
        } else {
            Self::Unknown(())
        }
    }
}

impl<A, R> From<Upward<A, R>> for Option<A> {
    fn from(value: Upward<A, R>) -> Self {
        if let Upward::Known(n) = value {
            Some(n)
        } else {
            None
        }
    }
}

impl<'de, A, R> serde::Deserialize<'de> for Upward<A, R>
where
    A: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        A::deserialize(deserializer).map(Upward::Known)
    }
}

impl<A, R> serde::Serialize for Upward<A, R>
where
    A: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if let Upward::Known(a) = self {
            a.serialize(serializer)
        } else {
            Err(serde::ser::Error::custom(format!(
                "Serializing `Upward::<{}>::Unknown` is not supported",
                type_name::<A>()
            )))
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Encountered unknown data from the Node API on type `Upward::<{type_name}>::Unknown`, which is required to be known.")]
pub struct UnknownDataError {
    type_name: &'static str,
}

impl UnknownDataError {
    pub fn new(type_name: &'static str) -> Self {
        Self { type_name }
    }
}

impl<A> std::iter::FromIterator<Upward<A>> for Upward<Vec<A>> {
    fn from_iter<T: IntoIterator<Item = Upward<A>>>(iter: T) -> Self {
        let mut vec = Vec::new();
        for a in iter {
            if let Upward::Known(a) = a {
                vec.push(a);
            } else {
                return Upward::Unknown(());
            }
        }
        Upward::Known(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upward_from_iterator_all_known() {
        let list = vec![Upward::Known(42); 50];
        let res = list.into_iter().collect::<Upward<_>>().unwrap();
        assert_eq!(vec![42; 50], res)
    }

    #[test]
    fn test_upward_from_iterator_some_unknown() {
        let mut list = vec![Upward::Known(42); 50];
        list[25] = Upward::Unknown(());
        let res = list.into_iter().collect::<Upward<_>>();
        assert_eq!(Upward::Unknown(()), res)
    }
}
