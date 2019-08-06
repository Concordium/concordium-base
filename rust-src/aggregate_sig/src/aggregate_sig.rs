use curve_arithmetic::Curve;
use curve_arithmetic::Pairing;
use pairing::Field;
use rand::Rng;
use rayon::iter::*;
use sha2::{Digest, Sha512};
use std::cmp::Ordering;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

use crate::errors::AggregateSigError;

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

#[derive(Debug)]
pub struct SecretKey<P: Pairing>(P::ScalarField);

impl<P: Pairing> SecretKey<P> {
    pub fn generate<R: Rng>(rng: &mut R) -> SecretKey<P> {
        SecretKey(P::generate_scalar(rng))
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey<P: Pairing>(P::G_2);

impl<P: Pairing> PublicKey<P> {
    pub fn from_secret(sk: &SecretKey<P>) -> PublicKey<P> {
        PublicKey(P::G_2::one_point().mul_by_scalar(&sk.0))
    }

    pub fn from_bytes(b: &mut Cursor<&[u8]>) -> Result<PublicKey<P>, AggregateSigError> {
        let point = P::G_2::bytes_to_curve(b)?;
        Ok(PublicKey(point))
    }

    pub fn to_bytes(&self) -> Box<[u8]> {
        P::G_2::curve_to_bytes(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct Signature<P: Pairing>(P::G_1);

// Sign a message using the supplied secret key.
// Signing can potentially be optimized by having a proper hash fucntion from the message space
// (&[u8]) to G_1. Currently we hash the message using Sha512 and decode it into a scalar of G_1
// and multiply the generator of G_1 with this
pub fn sign_message<P: Pairing>(message: &[u8], secret_key: &SecretKey<P>) -> Signature<P> {
    let mut scalar: P::ScalarField = scalar_from_message::<P>(message);
    // the hash is generator^scalar, the signature is hash^secret_key. We multiply scalars before
    // group operation for faster computation
    scalar.mul_assign(&secret_key.0);
    let signature = P::G_1::one_point().mul_by_scalar(&scalar);
    Signature(signature)
}

// Hashes the supplied message using Sha512 and decodes to the scalarfield of P, repeats until
// succesfully decoding.
fn scalar_from_message<P: Pairing>(m: &[u8]) -> P::ScalarField {
    let hashed_message = hash_message(m);
    match P::bytes_to_scalar(&mut Cursor::new(&hashed_message)) {
        Ok(scalar) => scalar,
        Err(_) => scalar_from_message::<P>(&hashed_message), // Perhaps set upper bound?
    }
}

// hashes a message using Sha512
fn hash_message(m: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    h.input(m);
    hash.copy_from_slice(h.result().as_slice());
    hash
}

// Verifies a single message and signature pair
pub fn verify<P: Pairing>(
    message: &[u8],
    public_key: &PublicKey<P>,
    signature: &Signature<P>,
) -> bool {
    let scalar: P::ScalarField = scalar_from_message::<P>(message);
    let g1_hash = P::G_1::one_point().mul_by_scalar(&scalar);
    P::pair(signature.0, P::G_2::one_point()) == P::pair(g1_hash, public_key.0)
}

// Aggregates the two signatures.
pub fn aggregate_sig<P: Pairing>(
    my_signature: &Signature<P>,
    aggregated_signature: &Signature<P>,
) -> Signature<P> {
    Signature(aggregated_signature.0.plus_point(&my_signature.0))
}

// Verifies a list of (message, public key) pairs with signature.
pub fn verify_aggregate_sig<P: Pairing>(
    m_pk_pairs: &[(&[u8], PublicKey<P>)],
    signature: &Signature<P>,
) -> bool {
    // check for duplicates in messages. Reject if any
    let ms: Vec<&[u8]> = m_pk_pairs.iter().map(|x| x.0).collect();
    if has_duplicates(ms) {
        return false;
    }

    let (m0, pk0) = &m_pk_pairs[0];
    let scalar0 = scalar_from_message::<P>(m0);
    let prod_so_far = Arc::new(Mutex::new(pk0.0.mul_by_scalar(&scalar0)));

    m_pk_pairs.par_iter().skip(1).for_each(|(m, pk)| {
        let scalar = scalar_from_message::<P>(m);
        let pk_mul = pk.0.mul_by_scalar(&scalar);
        let mut prod = prod_so_far.lock().unwrap();
        *prod = prod.plus_point(&pk_mul);
    });

    let prod = *prod_so_far.lock().unwrap();
    P::pair(signature.0, P::G_2::one_point()) == P::pair(P::G_1::one_point(), prod)
}

pub fn verify_aggregate_sig_trusted_keys<P: Pairing>(
    m: &[u8],
    pks: &[PublicKey<P>],
    signature: &Signature<P>,
) -> bool {
    let mut sum = pks[0].0;
    pks.iter().skip(1).for_each(|x| {
        sum = sum.plus_point(&x.0);
    });
    P::pair(signature.0, P::G_2::one_point())
        == P::pair(
            P::G_1::one_point().mul_by_scalar(&scalar_from_message::<P>(m)),
            sum,
        )
}
// Checks for duplicates in a list of messages
// This is not very efficient - the sorting algorithm can exit as soon as it encounters an equality
// and report that a duplicate indeed exists.
// Consider building hashmap or Btree and exit as soon as a duplicate is seen
fn has_duplicates(messages: Vec<&[u8]>) -> bool {
    let mut message_hashes: Vec<Hash> = messages
        .iter()
        .map(|x| {
            let h = hash_message(x);
            Hash(h)
        })
        .collect();
    message_hashes.sort();
    for i in 1..message_hashes.len() {
        if message_hashes[i - 1] == message_hashes[i] {
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

    const SIGNERS: usize = 10;
    const TEST_ITERATIONS: usize = 1000;

    // returns a pair of lists (sks, pks), such that sks[i] and pks[i] are corresponding secret and
    // public key
    macro_rules! get_sks_pks {
        ($amt:expr, $rng:expr) => {{
            let sks: Vec<SecretKey<Bls12>> = (0..$amt)
                .map(|_| SecretKey::<Bls12>::generate(&mut $rng))
                .collect();

            let pks: Vec<PublicKey<Bls12>> = sks
                .iter()
                .map(|x| PublicKey::<Bls12>::from_secret(x))
                .collect();

            (sks, pks)
        };};
    }

    // returns a list of random bytes (of length 32)
    macro_rules! get_random_messages {
        ($amt:expr, $rng:expr) => {{
            let ms: Vec<[u8; 32]> = (0..$amt).map(|_| $rng.gen::<[u8; 32]>()).collect();
            ms
        }};
    }

    #[test]
    fn test_sign_and_verify() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let sk = SecretKey::<Bls12>::generate(&mut rng);
        let pk = PublicKey::from_secret(&sk);

        for _ in 0..TEST_ITERATIONS {
            // should verify correctly
            let m = rng.gen::<[u8; 32]>();
            let signature = sign_message(&m, &sk);
            assert!(verify(&m, &pk, &signature));

            // should not verify!
            let signature = sign_message(&m, &sk);
            let sk2 = SecretKey::<Bls12>::generate(&mut rng);
            let pk2 = PublicKey::from_secret(&sk2);
            assert!(!verify(&m, &pk2, &signature))
        }
    }

    macro_rules! aggregate_sigs {
        ($messages:expr, $sks:expr) => {{
            let mut sig = sign_message(&$messages[0], &$sks[0]);
            for i in 1..$sks.len() {
                let my_sig = sign_message(&$messages[i], &$sks[i]);
                sig = aggregate_sig(&my_sig, &sig);
            }
            sig
        }};
    }

    #[test]
    fn test_verify_aggregate_sig() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let (sks, pks) = get_sks_pks!(SIGNERS, rng);

        for _ in 0..TEST_ITERATIONS {
            let ms = get_random_messages!(SIGNERS, rng);
            let sig = aggregate_sigs!(ms, sks);

            let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::new();
            for i in 0..SIGNERS {
                m_pk_pairs.push((&ms[i], pks[i].clone()));
            }

            // signature should verify
            assert!(verify_aggregate_sig(&m_pk_pairs, &sig));

            let (m_, pk_) = m_pk_pairs.pop().unwrap();
            let new_pk = PublicKey::<Bls12>::from_secret(&SecretKey::<Bls12>::generate(&mut rng));
            m_pk_pairs.push((m_, new_pk));

            // altering a public key should make verification fail
            assert!(!verify_aggregate_sig(&m_pk_pairs, &sig));

            let new_m: [u8; 32] = rng.gen::<[u8; 32]>();
            m_pk_pairs.pop();
            m_pk_pairs.push((&new_m, pk_));

            // altering a message should make verification fail
            assert!(!verify_aggregate_sig(&m_pk_pairs, &sig));
        }
    }

    #[test]
    fn test_verify_aggregate_sig_trusted_keys() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        for _ in 0..TEST_ITERATIONS {
            let (sks, pks) = get_sks_pks!(SIGNERS, rng);
            let m: [u8; 32] = rng.gen::<[u8; 32]>();
            let sigs: Vec<Signature<Bls12>> = sks.iter().map(|sk| sign_message(&m, &sk)).collect();
            let mut agg_sig = sigs[0].clone();
            sigs.iter().skip(1).for_each(|x| {
                agg_sig = aggregate_sig(&x, &agg_sig);
            });
            assert!(verify_aggregate_sig_trusted_keys(&m, &pks, &agg_sig));
        }
    }
    #[test]
    fn test_has_duplicates() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        for _ in 0..TEST_ITERATIONS {
            let mut ms: Vec<[u8; 8]> = (0..SIGNERS).map(|x| x.to_le_bytes()).collect();
            let random_idx1: usize = rng.gen_range(0, SIGNERS);
            let mut random_idx2: usize = rng.gen_range(0, SIGNERS);
            while random_idx1 == random_idx2 {
                random_idx2 = rng.gen_range(0, SIGNERS);
            }
            ms[random_idx1] = ms[random_idx2];

            let mut ms_pointers: Vec<&[u8]> = Vec::new();
            for i in 0..SIGNERS {
                ms_pointers.push(&ms[i]);
            }
            assert!(has_duplicates(ms_pointers));
        }
    }
}
