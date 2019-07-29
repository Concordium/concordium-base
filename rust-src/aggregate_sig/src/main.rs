use curve_arithmetic::Curve;
use curve_arithmetic::Pairing;
use pairing::Field;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::cmp::Ordering;
use std::io::Cursor;

struct Hash([u8; 64]);

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.0[0..63] == other.0[0..63]
    }
}

impl Eq for Hash {}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0[0..63].cmp(&other.0[0..63])
    }
}

pub struct SecretKey<P: Pairing>(P::ScalarField);

impl<P: Pairing> SecretKey<P> {
    pub fn generate<R: Rng>(rng: &mut R) -> SecretKey<P> {
        SecretKey(P::generate_scalar(rng))
    }
}

#[derive(Clone)]
pub struct PublicKey<P: Pairing>(P::G_2);

impl<P: Pairing> PublicKey<P> {
    pub fn from_secret(sk: &SecretKey<P>) -> PublicKey<P> {
        PublicKey(P::G_2::one_point().mul_by_scalar(&sk.0))
    }
}

pub struct Signature<P: Pairing>(P::G_1);

// Signing can potentially be optimized by having a proper hash fucntion from the message space
// (&[u8]) to G_1. Currently we hash and decode it into a scalar and multiply the generator of G_1
// with this scalar to hash into G_1
fn sign_message<P: Pairing>(secret_key: &SecretKey<P>, message: &[u8]) -> Signature<P> {
    let mut scalar: P::ScalarField = scalar_from_message::<P>(message);
    // the hash is generator^scalar, the signature is hash^secret_key. We multiply scalars before
    // group operation for faster computation
    scalar.mul_assign(&secret_key.0);
    let signature = P::G_1::one_point().mul_by_scalar(&scalar);
    Signature(signature)
}

// keeps hashing and decoding bytes to a scalar until succesful
fn scalar_from_message<P: Pairing>(m: &[u8]) -> P::ScalarField {
    let hashed_message = hash_message(m);
    match P::bytes_to_scalar(&mut Cursor::new(&hashed_message)) {
        Ok(scalar) => scalar,
        Err(_) => scalar_from_message::<P>(&hashed_message),
    }
}

// verifies a single signature. Should probably not be exposed, mainly used for testing.
// should probably not take ownership of signature
pub fn verify<P: Pairing>(
    message: &[u8],
    public_key: PublicKey<P>,
    signature: Signature<P>,
) -> bool {
    let scalar: P::ScalarField = scalar_from_message::<P>(message);
    let g1_hash = P::G_1::one_point().mul_by_scalar(&scalar);
    let left_hand_side = P::pair(signature.0, P::G_2::one_point());
    let right_hand_side = P::pair(g1_hash, public_key.0);
    left_hand_side == right_hand_side
}

// Signs the message using sk and aggregates the resulting signature to the supplied signature.
pub fn aggregate_sig<P: Pairing>(
    message: &[u8],
    sk: &SecretKey<P>,
    signature: Signature<P>,
) -> Signature<P> {
    let my_signature = sign_message(&sk, message);
    let aggregated_signature = signature.0.plus_point(&my_signature.0);
    Signature(aggregated_signature)
}

pub fn verify_aggregate_sig<P: Pairing>(
    messages: &[&[u8]],
    keys: &[PublicKey<P>],
    signature: Signature<P>,
) -> bool {
    if messages.len() != keys.len() || has_duplicates(messages) {
        return false;
    }
    let hash_m0 = scalar_from_message::<P>(&messages[0]);
    let mut rhs = P::pair(P::G_1::one_point().mul_by_scalar(&hash_m0), keys[0].0);
    for i in 1..messages.len() {
        let hash = scalar_from_message::<P>(&messages[i]);
        let multiplier = P::pair(P::G_1::one_point().mul_by_scalar(&hash), keys[i].0);
        rhs.mul_assign(&multiplier)
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

// this is not very efficient - the sorting algorithm can exit as soon as it encounters an equality
// and report that a duplicate indeed exists.
fn has_duplicates(messages: &[&[u8]]) -> bool {
    let mut message_hashes: Vec<Hash> = messages
        .iter()
        .map(|x| {
            let h = hash_message(x);
            Hash(h)
        })
        .collect();
    message_hashes.sort();
    for i in 1..messages.len() {
        if messages[i - 1] == messages[i] {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, StdRng};
    use std::mem;

    const SIGNERS: usize = 200;

    #[test]
    fn test_sign_and_verify() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        for _ in 1..10 {
            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let pk = PublicKey::from_secret(&sk);

            // should verify correctly
            let m = rng.gen::<[u8; 32]>();
            let signature = sign_message(&sk, &m);
            assert!(verify(&m, pk, signature));

            // should not verify!
            let signature = sign_message(&sk, &m);
            let sk2 = SecretKey::<Bls12>::generate(&mut rng);
            let pk2 = PublicKey::from_secret(&sk2);
            assert!(!verify(&m, pk2, signature))
        }
    }

    #[test]
    fn test_aggregate_sign_and_verify() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let sks: Vec<SecretKey<Bls12>> = (0..SIGNERS)
            .map(|_| SecretKey::<Bls12>::generate(&mut rng))
            .collect();

        let pks: Vec<PublicKey<Bls12>> = sks
            .iter()
            .map(|x| PublicKey::<Bls12>::from_secret(x))
            .collect();

        let ms: Vec<[u8; 32]> = (0..SIGNERS).map(|_| rng.gen::<[u8; 32]>()).collect();
        let mut sig = sign_message(&sks[0], &ms[0]);
        for i in 1..SIGNERS {
            sig = aggregate_sig(&ms[i], &sks[i], sig);
        }

        // build an array of pointers to the messages - not sure how to do it in a prettier way
        let ms_ = unsafe {
            let mut array: [&[u8]; SIGNERS] = mem::uninitialized();
            for i in 0..SIGNERS {
                array[i] = &ms[i]
            }
            array
        };
        assert!(verify_aggregate_sig(&ms_, &pks, sig));
    }

    // single case test with 2 messages, for quick testing while developing
    #[test]
    fn test_aggregate_sign_and_verify2() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let sk1: SecretKey<Bls12> = SecretKey::<Bls12>::generate(&mut rng);
        let sk2: SecretKey<Bls12> = SecretKey::<Bls12>::generate(&mut rng);
        let pk1: PublicKey<Bls12> = PublicKey::<Bls12>::from_secret(&sk1);
        let pk2: PublicKey<Bls12> = PublicKey::<Bls12>::from_secret(&sk2);
        let m1 = rng.gen::<[u8; 32]>();
        let m2 = rng.gen::<[u8; 32]>();

        let sig1 = sign_message(&sk1, &m1);
        let aggregate_sig = aggregate_sig(&m2, &sk2, sig1);
        assert!(verify_aggregate_sig(
            &[&m1, &m2],
            &[pk1, pk2],
            aggregate_sig
        ))
    }

    #[test]
    fn test_has_duplicates() {
        let mut ms: Vec<[u8; 8]> = (0..SIGNERS).map(|x| x.to_le_bytes()).collect();
        ms[1] = ms[2];

        // build an array of pointers to the messages - not sure how to do it in a prettier way
        let ms_ = unsafe {
            let mut array: [&[u8]; SIGNERS] = mem::uninitialized();
            for i in 0..SIGNERS {
                array[i] = &ms[i]
            }
            array
        };
        assert!(has_duplicates(&ms_));
    }

    // // Dumbed down sanity test, to be deleted
    // fn sanitychecker<P: Pairing>() {
    //     let mut csprng = thread_rng();
    //     let s1 = P::G_1::generate_scalar(&mut csprng);
    //     let s2 = P::G_1::generate_scalar(&mut csprng);
    //     let m1_scal = P::G_1::generate_scalar(&mut csprng);
    //     let m2_scal = P::G_1::generate_scalar(&mut csprng);
    //     let m1 = P::G_1::one_point().mul_by_scalar(&m1_scal);
    //     let m2 = P::G_1::one_point().mul_by_scalar(&m2_scal);
    //     // let m1 = P::G_1::one_point().mul_by_scalar(&P::G_1::generate_scalar(&mut csprng));
    //     // let m2 = P::G_1::one_point().mul_by_scalar(&P::G_1::generate_scalar(&mut csprng));
    //     let mut scal1 = m1_scal.clone();
    //     let mut scal2 = m2_scal.clone();
    //     scal1.mul_assign(&s1);
    //     scal2.mul_assign(&s2);
    //     let sig1 = P::G_1::one_point().mul_by_scalar(&scal1);
    //     let sig2 = P::G_1::one_point().mul_by_scalar(&scal2);
    //     // let sig1 = m1.mul_by_scalar(&s1);
    //     // let sig2 = m2.mul_by_scalar(&s2);
    //     let agg = sig1.plus_point(&sig2);
    //     let lhs = P::pair(agg, P::G_2::one_point());
    //     let mut rhs1 = P::pair(m1, P::G_2::one_point().mul_by_scalar(&s1));
    //     let rhs2 = P::pair(m2, P::G_2::one_point().mul_by_scalar(&s2));
    //     rhs1.mul_assign(&rhs2);
    //     assert!(lhs == rhs1);
    // }
    //
    // #[test]
    // fn sanity_test() {
    //     sanitychecker::<Bls12>();
    // }

    // TODO: add more realistic test cases of sign/verify, including signatures that are rejected
}

fn main() {
    println!("Hello, world!");
}
