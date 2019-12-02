// -*- mode: rust; -*-

//! A thin wrapper around a scalar to indicate that it is a secret value.

use crate::{curve_arithmetic::*, serialization::*};

use failure::Error;
use rand::*;
use std::{io::Cursor, ops::Deref};

/// A value that will be commited to.
/// NB: For the view function it is important that we have #[repr(transparent)].
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct Value<C: Curve> {
    pub value: C::Scalar,
}

// Overwrite value  material with null bytes when it goes out of scope.
// impl Drop for Value {
// fn drop(&mut self) {
// (self.0).into_repr().0.clear();
// }
// }

/// This trait allows automatic conversion of &Value<C> to &C::Scalar.
impl<C: Curve> Deref for Value<C> {
    type Target = C::Scalar;

    fn deref(&self) -> &C::Scalar { &self.value }
}

impl<C: Curve> Value<C> {
    pub fn new(value: C::Scalar) -> Self { Value { value } }

    // turn value vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let v = &self.value;
        let mut bytes: Vec<u8> = Vec::with_capacity(C::SCALAR_LENGTH);
        write_curve_scalar::<C>(v, &mut bytes);
        bytes.into_boxed_slice()
    }

    /// Construct a value  from a slice of bytes.
    ///
    /// A `Result` whose okay value is a Value vec  or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<Value<C>, Error> {
        let value = read_curve_scalar::<C>(cur)?;
        Ok(Value { value })
    }

    /// Generate a single `Value` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> Value<C>
    where
        T: Rng, {
        Value {
            value: C::generate_scalar(csprng),
        }
    }

    /// Generate a non-zero value `Value` from a `csprng`.
    pub fn generate_non_zero<T>(csprng: &mut T) -> Value<C>
    where
        T: Rng, {
        Value {
            value: C::generate_non_zero_scalar(csprng),
        }
    }

    /// Embed the Scalar as a value.
    pub fn from_scalar(value: C::Scalar) -> Self { Value { value } }

    /// View the value as a value in another group.
    #[inline]
    pub fn view<'a, T: Curve<Scalar = C::Scalar>>(&'a self) -> &'a Value<T> {
        unsafe {
            let Value { ref value } = self;
            &*(value as *const C::Scalar as *const Value<T>)
        }
    }

    /// View a scalar as a value.
    #[inline]
    pub fn view_scalar(scalar: &C::Scalar) -> &Self {
        unsafe { &*(scalar as *const C::Scalar as *const Value<C>) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1Affine, G2Affine};
    macro_rules! macro_test_value_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..20 {
                    let val = Value::<$curve_type>::generate(&mut csprng);
                    let res_val2 =
                        Value::<$curve_type>::from_bytes(&mut Cursor::new(&val.to_bytes()));
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }

    macro_test_value_to_byte_conversion!(value_to_byte_conversion_bls12_381_g1_affine, G1Affine);

    macro_test_value_to_byte_conversion!(value_to_byte_conversion_bls12_381_g2_affine, G2Affine);
}
