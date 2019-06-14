use crate::errors::{
    InternalError::{CurveDecodingError, FieldDecodingError, MessageVecLengthError},
    *,
};
use curve_arithmetic::curve_arithmetic::*;

use pairing::bls12_381::Bls12;

use curve_arithmetic::bls12_381_instance::*;
use rand::*;

#[derive(Debug)]
struct UnknownMessage<C: Pairing>(pub(crate) C::G_1);

impl<C: Pairing> PartialEq for UnknownMessage<C> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

impl<C: Pairing> Eq for UnknownMessage<C> {}

impl<C: Pairing> UnknownMessage<C> {
    // turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> { self.0.curve_to_bytes() }

    /// Construct a commitment from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<UnknownMessage<C>, SignatureError> {
        match C::G_1::bytes_to_curve(bytes) {
            Ok(point) => Ok(UnknownMessage(point)),
            Err(x) => Err(SignatureError(CurveDecodingError)),
        }
    }

    pub fn arbitrary<T: Rng>(csprng: &mut T) -> UnknownMessage<C> {
        UnknownMessage(C::G_1::generate(csprng))
    }
}

macro_rules! macro_test_unknown_message_to_byte_conversion {
    ($function_name:ident, $pairing_type:path) => {
        #[test]
        pub fn $function_name() {
            let mut csprng = thread_rng();
            for _i in 0..20 {
                let x = UnknownMessage::<$pairing_type>::arbitrary(&mut csprng);
                let y = UnknownMessage::<$pairing_type>::from_bytes(&*x.to_bytes());
                assert!(y.is_ok());
                assert_eq!(x, y.unwrap());
            }
        }
    };
}
macro_test_unknown_message_to_byte_conversion!(unknown_message_to_byte_conversion_bls12_381, Bls12);
