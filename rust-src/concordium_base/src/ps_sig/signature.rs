use super::unknown_message::SigRetrievalRandomness;
use crate::curve_arithmetic::*;
use rand::*;

use crate::common::*;

/// Randomness used to blind a signature.
#[derive(Debug, Eq, Serialize)]
pub struct BlindingRandomness<P: Pairing>(pub Secret<P::ScalarField>, pub Secret<P::ScalarField>);

/// Manual implementation to relax the requirements on `P`. The derived
/// instance would have required P to have `PartialEq`.
impl<P: Pairing> PartialEq for BlindingRandomness<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
/// Type wrapper around a signature, indicating that it is a blinded variant.
pub struct BlindedSignature<P: Pairing> {
    pub sig: Signature<P>,
}

/// Tried to create a signature whose first component is the identity of `G1`.
#[derive(Debug, thiserror::Error)]
#[error("the first component of a signature cannot be the identity of G1")]
pub struct ZeroSignature;

#[derive(Debug, Clone, Serial)]
/// A signature $(a, b)$ on a [KnownMessage](super::KnownMessage).
///
/// The first component of a signature is never the identity of `G1`. This is an
/// invariant of the type: the components are not public, and the only ways of
/// obtaining a signature all maintain it, see [`Signature::try_new`].
pub struct Signature<C: Pairing>(pub(super) C::G1, pub(super) C::G1);

impl<C: Pairing> Deserial for Signature<C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let a: C::G1 = source.get()?;
        let b: C::G1 = source.get()?;
        Ok(Signature::try_new(a, b)?)
    }
}

impl<C: Pairing> PartialEq for Signature<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl<C: Pairing> Eq for Signature<C> {}

impl<C: Pairing> Signature<C> {
    /// Construct a signature from its two components $(a, b)$.
    ///
    /// This fails if `a` is the identity of `G1`. Such a signature is
    /// degenerate: it satisfies the verification equation for *any* message,
    /// and it makes the proofs of knowledge of a signature (see
    /// [`com_eq_sig`](crate::sigma_protocols::com_eq_sig) and
    /// [`ps_sig_known`](crate::sigma_protocols::ps_sig_known)) satisfiable
    /// without knowing a signature at all. It must therefore never be
    /// constructed, which is what makes the check in
    /// [`PublicKey::verify`](super::PublicKey::verify) sufficient for the
    /// protocols built on top of the signature scheme.
    pub fn try_new(a: C::G1, b: C::G1) -> Result<Self, ZeroSignature> {
        if a.is_zero_point() {
            Err(ZeroSignature)
        } else {
            Ok(Signature(a, b))
        }
    }

    /// The first component $a$ of the signature. It is never the identity of
    /// `G1`.
    pub fn a(&self) -> C::G1 {
        self.0
    }

    /// The second component $b$ of the signature.
    pub fn b(&self) -> C::G1 {
        self.1
    }

    /// Construct a signature without checking the invariant on the first
    /// component. Only available in tests, where degenerate signatures are
    /// needed to check that the protocols reject them.
    #[cfg(test)]
    pub(crate) fn new_unchecked(a: C::G1, b: C::G1) -> Signature<C> {
        Signature(a, b)
    }

    /// Generate a valid (in the sense of representation) but otherwise
    /// arbitrary signature. Exposed because it is useful for testing protocols
    /// on top of the signature scheme.
    pub fn arbitrary<T: Rng>(csprng: &mut T) -> Signature<C> {
        // not a proper signature to be used for testing serialization
        Signature(
            // The first component must not be the identity of G1, so it is sampled as a
            // non-zero multiple of the generator rather than uniformly in G1.
            C::G1::one_point().mul_by_scalar(&C::generate_non_zero_scalar(csprng)),
            C::G1::generate(csprng),
        )
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
    type Bls12 = ark_ec::models::bls12::Bls12<ark_bls12_381::Config>;

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

    /// A signature whose first component is the identity of G1 must be rejected,
    /// both when constructed and when parsed, and both as a `Signature` and as a
    /// `BlindedSignature`, since such a signature makes the proofs of knowledge
    /// of a signature trivially satisfiable. A zero *second* component is not a
    /// problem, and is thus still accepted.
    macro_rules! macro_test_zero_signature_rejected {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                type G1 = <$pairing_type as Pairing>::G1;
                type Sig = Signature<$pairing_type>;
                let mut csprng = thread_rng();

                let non_zero = G1::generate(&mut csprng);
                assert!(Sig::try_new(G1::zero_point(), G1::zero_point()).is_err());
                assert!(Sig::try_new(G1::zero_point(), non_zero).is_err());
                assert!(Sig::try_new(non_zero, G1::zero_point()).is_ok());

                for sig in [
                    Sig::new_unchecked(G1::zero_point(), G1::zero_point()),
                    Sig::new_unchecked(G1::zero_point(), non_zero),
                ] {
                    assert!(
                        serialize_deserialize(&sig).is_err(),
                        "A signature with a zero first component must not be deserialized as a \
                         Signature."
                    );
                    assert!(
                        serialize_deserialize(&BlindedSignature::<$pairing_type> { sig }).is_err(),
                        "A signature with a zero first component must not be deserialized as a \
                         BlindedSignature."
                    );
                }

                // Only the first component is restricted.
                let zero_second = Sig::new_unchecked(non_zero, G1::zero_point());
                assert_eq!(
                    serialize_deserialize(&zero_second).expect(
                        "A signature with a zero second component should still be deserialized."
                    ),
                    zero_second
                );
            }
        };
    }

    macro_test_zero_signature_rejected!(zero_signature_rejected_bls12_381, Bls12);
}
