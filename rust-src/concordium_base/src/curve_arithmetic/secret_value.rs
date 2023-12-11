// -*- mode: rust; -*-

//! A thin wrapper around a scalar to indicate that it is a secret value.

use crate::{common::*, curve_arithmetic::*};
use rand::*;
use std::{
    ops::{Deref, Drop},
    ptr,
    rc::Rc,
    sync::atomic,
};

/// A generic wrapper for a secret that implements a zeroize on drop.
/// Other types are expected to wrap this in more convenient interfaces.
/// Ideally the constraint would be Default, but fields we have do not implement
/// it, so we cannot use it at the moment. Hence the temporary hack of 'T:
/// Field'.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Secret<T: Field + Serialize> {
    secret: T,
}

impl<F: Field + Serialize> Secret<F> {
    pub fn new(secret: F) -> Self { Secret { secret } }
}

impl<F: Field + Serialize> AsRef<F> for Secret<F> {
    fn as_ref(&self) -> &F { &self.secret }
}

impl<F: Field + Serialize> Deref for Secret<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target { &self.secret }
}

// This works for our current fields since they are arrays
// But in the future we need to revisit, especially if our
// upstream dependencies decide to implement drop themselves.
impl<F: Field + Serialize> Drop for Secret<F> {
    fn drop(&mut self) {
        // This implementation is what the Zeroize trait implementations do.
        // It protects against most reorderings by the compiler.
        unsafe { ptr::write_volatile(&mut self.secret, F::zero()) }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

/// A secret value. The idea of this datatype is to mark
/// some scalars as secret, so that their use is harder and there is
/// no implicit copy.
#[derive(Debug, PartialEq, Eq, Serialize, Clone, SerdeBase16Serialize)]
pub struct Value<C: Curve> {
    pub value: Rc<Secret<C::Scalar>>,
}

/// This trait allows automatic conversion of `&Value<C>` to `&C::Scalar`.
impl<C: Curve> Deref for Value<C> {
    type Target = C::Scalar;

    fn deref(&self) -> &C::Scalar { &self.value }
}

impl<C: Curve> AsRef<C::Scalar> for Value<C> {
    fn as_ref(&self) -> &C::Scalar { &self.value }
}

/// Any 64-bit value can be converted (by-value) to a scalar.
impl<C: Curve> From<u64> for Value<C> {
    fn from(secret: u64) -> Self { Self::new(C::scalar_from_u64(secret)) }
}

impl<C: Curve> Value<C> {
    pub fn new(secret: C::Scalar) -> Self {
        Self {
            value: Rc::new(Secret::new(secret)),
        }
    }

    /// Generate a single `Value` from a `csprng`.
    pub fn generate<T: Rng>(csprng: &mut T) -> Value<C> { Value::new(C::generate_scalar(csprng)) }

    /// Generate a non-zero value `Value` from a `csprng`.
    pub fn generate_non_zero<T: Rng>(csprng: &mut T) -> Value<C> {
        Value::new(C::generate_non_zero_scalar(csprng))
    }

    /// View the value as a value in another group. This does not
    /// copy the secret value.
    #[inline]
    pub fn view<T: Curve<Scalar = C::Scalar>>(&self) -> Value<T> {
        Value {
            value: self.value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{G1Projective, G2Projective};

    use crate::curve_arithmetic::arkworks_instances::ArkGroup;

    use super::*;
    macro_rules! macro_test_value_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..20 {
                    let val = Value::<$curve_type>::generate(&mut csprng);
                    let res_val2 = serialize_deserialize(&val);
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }

    // TODO: the code used to be diefined using the affine representation, but
    // ArkWorks' BLS does not implement `CurveGroup` for the affine representation.
    // Is it important that it's the affine representation? For now, the BLS
    // projective representation will be used here.
    macro_test_value_to_byte_conversion!(
        value_to_byte_conversion_bls12_381_g1_affine,
        ArkGroup<G1Projective>
    );

    macro_test_value_to_byte_conversion!(
        value_to_byte_conversion_bls12_381_g2_affine,
        ArkGroup<G2Projective>
    );
}
