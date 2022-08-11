use crate::unknown_message::SigRetrievalRandomness;
use curve_arithmetic::*;
use rand::*;

use crypto_common::*;

/// Randomness used to blind a signature.
#[derive(Debug, Eq, Serialize)]
pub struct BlindingRandomness<P: Pairing>(pub Secret<P::ScalarField>, pub Secret<P::ScalarField>);

/// Manual implementation to relax the requirements on `P`. The derived
/// instance would have required P to have `PartialEq`.
impl<P: Pairing> PartialEq for BlindingRandomness<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 && self.1 == other.1 }
}

#[repr(transparent)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
/// Type wrapper around a signature, indicating that it is a blinded variant.
pub struct BlindedSignature<P: Pairing> {
    pub sig: Signature<P>,
}

#[derive(Debug, Clone, Serialize)]
/// A signature on a [KnownMessage](super::KnownMessage).
pub struct Signature<C: Pairing>(pub C::G1, pub C::G1);

impl<C: Pairing> PartialEq for Signature<C> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 && self.1 == other.1 }
}

impl<C: Pairing> Eq for Signature<C> {}

impl<C: Pairing> Signature<C> {
    /// Generate a valid (in the sense of representation) but otherwise
    /// arbitrary signature. Exposed because it is useful for testing protocols
    /// on top of the signature scheme.
    pub fn arbitrary<T: Rng>(csprng: &mut T) -> Signature<C> {
        // not a proper signature to be used for testing serialization
        Signature(C::G1::generate(csprng), C::G1::generate(csprng))
    }

    /// Retrieves a signature on the original message from the signature on the
    /// commitment, and the randomness used in the commitment.
    pub fn retrieve(&self, r: &SigRetrievalRandomness<C>) -> Self {
        let h = self.0;
        let hr = h.mul_by_scalar(r);
        let b = self.1;
        Signature(h, b.minus_point(&hr))
    }

    /// Blind a signature.
    pub fn blind<R: Rng>(&self, csprng: &mut R) -> (BlindedSignature<C>, BlindingRandomness<C>) {
        let r = C::generate_non_zero_scalar(csprng);
        let t = C::generate_non_zero_scalar(csprng);
        let Signature(a, b) = self;
        let a_hid = a.mul_by_scalar(&r);
        let b_hid = b.plus_point(&a.mul_by_scalar(&t)).mul_by_scalar(&r);
        let sig = Signature(a_hid, b_hid);
        let randomness = BlindingRandomness(Secret::new(r), Secret::new(t));
        (BlindedSignature { sig }, randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    macro_rules! macro_test_signature_to_byte_conversion {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 0..20 {
                    let x = Signature::<$pairing_type>::arbitrary(&mut csprng);
                    let y = serialize_deserialize(&x);
                    assert!(y.is_ok());
                    assert_eq!(x, y.unwrap());
                }
            }
        };
    }

    macro_test_signature_to_byte_conversion!(signature_to_byte_conversion_bls12_381, Bls12);
}
