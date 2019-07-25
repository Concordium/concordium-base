use curve_arithmetic::Curve;
use curve_arithmetic::Pairing;
use pairing::Field;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::io::Cursor;

// Currently using wrapper for message to implement the trait PartialEq needed for checking for
// duplicate messages in fn has_duplicates,
// Should use Rust native byte comparison operators instead (TODO)
struct Message<'a>(&'a [u8]);

// not optimized, bytewise comparison of two messages
impl<'a> PartialEq for Message<'a> {
    fn eq(&self, other: &Self) -> bool {
        for i in 1..self.0.len() {
            if self.0[i] != other.0[i] {
                return false;
            }
        }
        true
    }
}

struct SecretKey<P: Pairing>(P::ScalarField);

impl<P: Pairing> SecretKey<P> {
    fn generate<R: Rng>(rng: &mut R) -> SecretKey<P> {
        SecretKey(P::generate_scalar(rng))
    }
}

#[derive(Clone)]
struct PublicKey<P: Pairing>(P::G_2);

impl<P: Pairing> PublicKey<P> {
    fn from_secret(sk: &SecretKey<P>) -> PublicKey<P> {
        PublicKey(P::G_2::one_point().mul_by_scalar(&sk.0))
    }
}

struct Signature<P: Pairing>(P::G_1);

// Signing can potentially be optimized by having a proper hash fucntion from the message space
// (&[u8]) to G_1. Currently we hash and decode it into a scalar and multiply the generator of G_1
// with this scalar to hash into G_1
fn sign_message<P: Pairing>(secret_key: &SecretKey<P>, message: &Message) -> Signature<P> {
    let mut scalar: P::ScalarField = scalar_from_message::<P>(message.0);
    // the hash is generator^scalar, the signature is hash^secret_key. We multiply scalars before
    // group operation for faster computation
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
fn verify<P: Pairing>(
    message: &Message,
    public_key: PublicKey<P>,
    signature: Signature<P>,
) -> bool {
    let scalar: P::ScalarField = scalar_from_message::<P>(message.0);
    let g1_hash = P::G_1::one_point().mul_by_scalar(&scalar);
    let left_hand_side = P::pair(signature.0, P::G_2::one_point());
    let right_hand_side = P::pair(g1_hash, public_key.0);
    left_hand_side == right_hand_side
}

// Signs the message using sk and aggregates the resulting signature to the supplied signature.
fn aggregate_sig<P: Pairing>(
    message: &Message,
    sk: &SecretKey<P>,
    signature: Signature<P>,
) -> Signature<P> {
    let my_signature = sign_message(&sk, &message);
    let aggregated_signature = signature.0.plus_point(&my_signature.0);
    Signature(aggregated_signature)
}

fn verify_aggregate_sig<P: Pairing>(
    messages: &[Message],
    keys: &[PublicKey<P>],
    signature: Signature<P>,
) -> bool {
    if has_duplicates(messages) || messages.len() != keys.len() {
        //return false
        // TODO: check for duplicate messages
    }
    let hash_m0 = scalar_from_message::<P>(&messages[0].0);
    let mut rhs = P::pair(P::G_1::one_point().mul_by_scalar(&hash_m0), keys[0].0);
    for i in 1..messages.len() {
        let hash = scalar_from_message::<P>(&messages[i].0);
        let multiplier = P::pair(P::G_1::one_point().mul_by_scalar(&hash), keys[i].0);
        rhs.mul_assign(&multiplier) // use something more optimized than mul_assign, ask Ales and/or Bassel
    }
    let lhs = P::pair(signature.0, P::G_2::one_point());
    lhs == rhs
}

fn hash_message(m: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    h.input(m);
    hash.copy_from_slice(h.result().as_slice());
    hash
}

// this is not efficient!!! needs to be optimized
fn has_duplicates(messages: &[Message]) -> bool {
    for i in 1..messages.len() {
        if messages[i..].contains(&messages[i - 1]) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::thread_rng;
    use rand::{Rng, SeedableRng, StdRng};

    #[test]
    fn test_sign_and_verify() {
        let mut csprng = thread_rng();
        let sk = SecretKey::<Bls12>::generate(&mut csprng);
        let pk = PublicKey::from_secret(&sk);

        // should verify correctly
        let m = Message(&[1u8, 64]);
        let signature = sign_message(&sk, &m);
        assert!(verify(&m, pk, signature));

        // should not verify!
        let signature = sign_message(&sk, &m);
        let sk2 = SecretKey::<Bls12>::generate(&mut csprng);
        let pk2 = PublicKey::from_secret(&sk2);
        assert!(!verify(&m, pk2, signature))
    }

    #[test]
    fn test_aggregate_sign_and_verify() {
        let mut csprng = thread_rng();
        let sks: Vec<SecretKey<Bls12>> = (0..10)
            .map(|x| SecretKey::<Bls12>::generate(&mut csprng))
            .collect();
        let pks: Vec<PublicKey<Bls12>> = sks
            .iter()
            .map(|x| PublicKey::<Bls12>::from_secret(x))
            .collect();
        let ms_: Vec<[u8; 32]> = (0..10).map(|x| csprng.gen::<[u8; 32]>()).collect();
        let ms: Vec<Message> = ms_.iter().map(|x| Message(x)).collect();
        let mut sig = sign_message(&sks[0], &ms[0]);
        for i in 1..10 {
            sig = aggregate_sig(&ms[i], &sks[i], sig);
        }
        assert!(verify_aggregate_sig(&ms, &pks, sig))
    }

    #[test]
    fn test_aggregate_sign_and_verify2() {
        let mut csprng = thread_rng();
        let sk1: SecretKey<Bls12> = SecretKey::<Bls12>::generate(&mut csprng);
        let sk2: SecretKey<Bls12> = SecretKey::<Bls12>::generate(&mut csprng);
        let pk1: PublicKey<Bls12> = PublicKey::<Bls12>::from_secret(&sk1);
        let pk2: PublicKey<Bls12> = PublicKey::<Bls12>::from_secret(&sk2);
        let m1_ = csprng.gen::<[u8; 32]>();
        let m1 = Message(&m1_);
        let m2_ = csprng.gen::<[u8; 32]>();
        let m2 = Message(&m2_);

        let sig1 = sign_message(&sk1, &m1);
        let aggregate_sig = aggregate_sig(&m2, &sk2, sig1);
        assert!(verify_aggregate_sig(&[m1, m2], &[pk1, pk2], aggregate_sig))
    }

    // Dumbed down sanity test, to be deleted
    fn sanitychecker<P: Pairing>() {
        let mut csprng = thread_rng();
        let s1 = P::G_1::generate_scalar(&mut csprng);
        let s2 = P::G_1::generate_scalar(&mut csprng);
        let m1_scal = P::G_1::generate_scalar(&mut csprng);
        let m2_scal = P::G_1::generate_scalar(&mut csprng);
        let m1 = P::G_1::one_point().mul_by_scalar(&m1_scal);
        let m2 = P::G_1::one_point().mul_by_scalar(&m2_scal);
        // let m1 = P::G_1::one_point().mul_by_scalar(&P::G_1::generate_scalar(&mut csprng));
        // let m2 = P::G_1::one_point().mul_by_scalar(&P::G_1::generate_scalar(&mut csprng));
        let mut scal1 = m1_scal.clone();
        let mut scal2 = m2_scal.clone();
        scal1.mul_assign(&s1);
        scal2.mul_assign(&s2);
        let sig1 = P::G_1::one_point().mul_by_scalar(&scal1);
        let sig2 = P::G_1::one_point().mul_by_scalar(&scal2);
        // let sig1 = m1.mul_by_scalar(&s1);
        // let sig2 = m2.mul_by_scalar(&s2);
        let agg = sig1.plus_point(&sig2);
        let lhs = P::pair(agg, P::G_2::one_point());
        let mut rhs1 = P::pair(m1, P::G_2::one_point().mul_by_scalar(&s1));
        let rhs2 = P::pair(m2, P::G_2::one_point().mul_by_scalar(&s2));
        rhs1.mul_assign(&rhs2);
        assert!(lhs == rhs1);
    }

    #[test]
    fn sanity_test() {
        sanitychecker::<Bls12>();
    }
    // TODO: add more realistic test cases of sign/verify, including signatures that are rejected
}

fn main() {
    println!("Hello, world!");
}
