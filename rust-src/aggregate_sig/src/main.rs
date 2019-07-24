use curve_arithmetic::Curve;
use curve_arithmetic::Pairing;
use pairing::Field;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::io::Cursor;

struct SecretKey<P: Pairing>(P::ScalarField);

impl<P: Pairing> SecretKey<P> {
    fn generate<R: Rng>(rng: &mut R) -> SecretKey<P> {
        SecretKey(P::generate_scalar(rng))
    }
}

struct PublicKey<P: Pairing>(P::G_2);

impl<P: Pairing> PublicKey<P> {
    fn from_secret(sk: &SecretKey<P>) -> PublicKey<P> {
        PublicKey(P::G_2::one_point().mul_by_scalar(&sk.0))
    }
}

struct Signature<P: Pairing>(P::G_1);

// Signing can potentially be optimized by having a proper hash fucntion from the message space
// (bytes) to G_1. Currently we decode it into a scalar and multiply the generator of G_1 with this
// scalar to hash into G_1
fn sign_message<P: Pairing>(secret_key: &SecretKey<P>, message: &[u8]) -> Signature<P> {
    let mut scalar: P::ScalarField = scalar_from_message::<P>(message);
    // the hash is generator^scalar, the signature is hash^secret_key. We multiply scalars before
    // group operation for optimization
    scalar.mul_assign(&secret_key.0);
    let signature = P::G_1::one_point().mul_by_scalar(&scalar);
    Signature(signature)
}

// keeps hashing and decoding bytes to a scalar until succesful
fn scalar_from_message<P: Pairing>(m: &[u8]) -> P::ScalarField {
    let mut h: Sha512 = Sha512::new();
    h.input(m);
    let hashed_message = h.result();
    let as_slice = hashed_message.as_slice();
    match P::bytes_to_scalar(&mut Cursor::new(as_slice)) {
        Ok(scalar) => scalar,
        Err(_) => scalar_from_message::<P>(as_slice),
    }
}

// verifies a single signature. Should probably not be exposed, mainly used for testing.
// should probably not take ownership of signature
fn verify<P: Pairing>(message: &[u8], public_key: PublicKey<P>, signature: Signature<P>) -> bool {
    let scalar: P::ScalarField = scalar_from_message::<P>(message);
    let g1_hash = P::G_1::one_point().mul_by_scalar(&scalar);
    let left_hand_side = P::pair(signature.0, P::G_2::one_point());
    let right_hand_side = P::pair(g1_hash, public_key.0);
    left_hand_side == right_hand_side
}

// Signs the message using sk and aggregates the resulting signature to the supplied signature.
fn aggregate_sig<P: Pairing>(
    message: &[u8],
    sk: SecretKey<P>,
    signature: Signature<P>,
) -> Signature<P> {
    let my_signature = sign_message(&sk, message);
    let aggregated_signature = signature.0.plus_point(&my_signature.0);
    Signature(aggregated_signature)
}

fn verify_aggregate_sig<P: Pairing>(
    messages: &[(&[u8], PublicKey<P>)],
    signature: Signature<P>,
) -> bool {
    true // TODO
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::thread_rng;

    #[test]
    fn test_sign_and_verify() {
        let mut csprng = thread_rng();
        let sk = SecretKey::<Bls12>::generate(&mut csprng);
        let pk = PublicKey::from_secret(&sk);

        // should verify correctly
        let m = [1u8, 64];
        let signature = sign_message(&sk, &m);
        assert!(verify(&m, pk, signature));

        // should not verify!
        let signature = sign_message(&sk, &m);
        let sk2 = SecretKey::<Bls12>::generate(&mut csprng);
        let pk2 = PublicKey::from_secret(&sk2);
        assert!(!verify(&m, pk2, signature))
    }

    // TODO: add more realistic test cases of sign/verify, including signatures that are rejected
}

fn main() {
    println!("Hello, world!");
}
