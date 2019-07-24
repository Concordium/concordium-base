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

fn main() {
    println!("Hello, world!");
}
