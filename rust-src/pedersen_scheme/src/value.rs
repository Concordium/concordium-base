// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! A value
//! The object being commitmed to

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use curve_arithmetic::{curve_arithmetic::*, serialization::*};

use failure::Error;
use rand::*;
use std::io::Cursor;

/// A  value
#[derive(Debug, PartialEq, Eq)]
pub struct Value<C: Curve>(pub C::Scalar);

// Overwrite value  material with null bytes when it goes out of scope.
// impl Drop for Value {
// fn drop(&mut self) {
// (self.0).into_repr().0.clear();
// }
// }

impl<C: Curve> Value<C> {
    // turn value vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let v = &self.0;
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
        let vs = read_curve_scalar::<C>(cur)?;
        Ok(Value(vs))
    }

    /// Generate a sing `Value` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> Value<C>
    where
        T: Rng, {

        Value(C::generate_scalar(csprng))
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
