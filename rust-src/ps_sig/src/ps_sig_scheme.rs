use crate::{public::*, signature::*, unknown_message::*};
use curve_arithmetic::curve_arithmetic::*;

use pedersen_scheme::{commitment::Commitment, key::CommitmentKey, value::*};
use rand::*;

// A method to generate a commitment key from the public key
pub fn commitment_key<C: Pairing>(pk: &PublicKey<C>) -> CommitmentKey<C::G_1> {
    CommitmentKey::new(pk.0.clone(), C::G_1::one_point())
}

// transforms a commitment into an unknown message
// should be done better
// there should be a trait for commitment scheme
pub fn message<C: Pairing>(commitment: &Commitment<C::G_1>) -> UnknownMessage<C> {
    let point = commitment.0;
    UnknownMessage(point)
}

pub fn commit_with_pk<C: Pairing>(
    pk: &PublicKey<C>,
    vs: &Value<C::G_1>,
) -> (UnknownMessage<C>, C::ScalarField) {
    let ck = commitment_key(&pk);
    let mut csprng = thread_rng();
    let (commitment, randomness) = ck.commit(&vs, &mut csprng);
    (message(&commitment), randomness)
}

// retrieves a signature on the original message from the signature on the
// commitment
pub fn retrieve_sig<C: Pairing>(sig: &Signature<C>, r: C::ScalarField) -> Signature<C> {
    let h = sig.0;
    let hr = h.mul_by_scalar(&r);
    let b = sig.1;
    Signature(sig.0, b.minus_point(&hr))
}
