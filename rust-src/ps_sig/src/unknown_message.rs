use crate::errors::{InternalError::CurveDecodingError, *};
use curve_arithmetic::{curve_arithmetic::*, serialization::*};
use rand::*;
use std::{io::Cursor, ops::Deref};

#[derive(Debug)]
pub struct UnknownMessage<C: Pairing>(pub C::G_1);

impl<C: Pairing> PartialEq for UnknownMessage<C> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

impl<C: Pairing> Eq for UnknownMessage<C> {}

/// This trait allows automatic conversion of &Value<C> to &C::Scalar.
impl<P: Pairing> Deref for UnknownMessage<P> {
    type Target = P::G_1;

    fn deref(&self) -> &P::G_1 { &self.0 }
}

/// Randomness used to retrieve signature on the message from signature on an
/// unknown message.
#[derive(Debug)]
#[repr(transparent)]
pub struct SigRetrievalRandomness<P: Pairing> {
    pub randomness: P::ScalarField,
}

impl<P: Pairing> Deref for SigRetrievalRandomness<P> {
    type Target = P::ScalarField;

    fn deref(&self) -> &P::ScalarField { &self.randomness }
}

impl<P: Pairing> SigRetrievalRandomness<P> {
    pub fn to_bytes(&self) -> Box<[u8]> { P::G_1::scalar_to_bytes(&self.randomness) }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let scalar = read_curve_scalar::<P::G_1>(cur).ok()?;
        Some(SigRetrievalRandomness { randomness: scalar })
    }
}

impl<C: Pairing> UnknownMessage<C> {
    // turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> { self.0.curve_to_bytes() }

    /// Construct a commitment from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<UnknownMessage<C>, SignatureError> {
        match C::G_1::bytes_to_curve(bytes) {
            Ok(point) => Ok(UnknownMessage(point)),
            Err(_) => Err(SignatureError(CurveDecodingError)),
        }
    }

    /// Generate a valid, but arbitrary message. Exposed because it can be used
    /// for testing protocols built on top of the signature scheme.
    pub fn arbitrary<T: Rng>(csprng: &mut T) -> UnknownMessage<C> {
        UnknownMessage(C::G_1::generate(csprng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    macro_rules! macro_test_unknown_message_to_byte_conversion {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 0..20 {
                    let x = UnknownMessage::<$pairing_type>::arbitrary(&mut csprng);
                    let y = UnknownMessage::<$pairing_type>::from_bytes(&mut Cursor::new(
                        &x.to_bytes(),
                    ));
                    assert!(y.is_ok());
                    assert_eq!(x, y.unwrap());
                }
            }
        };
    }
    macro_test_unknown_message_to_byte_conversion!(
        unknown_message_to_byte_conversion_bls12_381,
        Bls12
    );
}
