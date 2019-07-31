use curve_arithmetic::Curve;
use curve_arithmetic::Pairing;
use pairing::Field;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::cmp::Ordering;
use std::io::Cursor;

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

// Signing can potentially be optimized by having a proper hash fucntion from the message space
// (&[u8]) to G_1. Currently we hash and decode it into a scalar and multiply the generator of G_1
// with this scalar to hash into G_1
pub fn sign_message<P: Pairing>(secret_key: &SecretKey<P>, message: &[u8]) -> Signature<P> {
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
        Err(_) => scalar_from_message::<P>(&hashed_message), // Perhaps set upper bound?
    }
}

// verifies a single signature. Should probably not be exposed, mainly used for testing.
// should probably not take ownership of signature
pub fn verify<P: Pairing>(
    message: &[u8],
    public_key: &PublicKey<P>,
    signature: &Signature<P>,
) -> bool {
    let scalar: P::ScalarField = scalar_from_message::<P>(message);
    let g1_hash = P::G_1::one_point().mul_by_scalar(&scalar);
    P::pair(signature.0, P::G_2::one_point()) == P::pair(g1_hash, public_key.0)
}

// Signs the message using sk and aggregates the resulting signature to the supplied signature.
pub fn aggregate_sig<P: Pairing>(
    my_signature: Signature<P>,
    aggregated_signature: Signature<P>,
) -> Signature<P> {
    Signature(aggregated_signature.0.plus_point(&my_signature.0))
}

pub fn verify_aggregate_sig_v1<P: Pairing>(
    m_pk_pairs: &[(&[u8], PublicKey<P>)],
    signature: Signature<P>,
) -> bool {
    let ms: Vec<&[u8]> = m_pk_pairs.iter().map(|x| x.0).collect();
    if has_duplicates(ms) {
        return false;
    }
    let hash_m0 = scalar_from_message::<P>(m_pk_pairs[0].0);
    let mut rhs = P::pair(
        P::G_1::one_point().mul_by_scalar(&hash_m0),
        (m_pk_pairs[0].1).0,
    );
    for i in 1..m_pk_pairs.len() {
        let (m, pk) = &m_pk_pairs[i];
        let hash = scalar_from_message::<P>(m);
        let multiplier = P::pair(P::G_1::one_point().mul_by_scalar(&hash), pk.0);
        rhs.mul_assign(&multiplier)
    }
    let lhs = P::pair(signature.0, P::G_2::one_point());
    lhs == rhs
}

pub fn verify_aggregate_sig_v2<P: Pairing>(
    m_pk_pairs: &[(&[u8], PublicKey<P>)],
    signature: Signature<P>,
) -> bool {
    // check for duplicates
    let ms: Vec<&[u8]> = m_pk_pairs.iter().map(|x| x.0).collect();
    if has_duplicates(ms) {
        return false;
    }

    let scalar = scalar_from_message::<P>(m_pk_pairs[0].0);
    let fold_init = (m_pk_pairs[0].1).0.mul_by_scalar(&scalar);
    let product_of_pks_mul_by_hash: P::G_2 =
        m_pk_pairs.iter().skip(1).fold(fold_init, |product, x| {
            let scalar = scalar_from_message::<P>(x.0);
            let pk_multiplied = (x.1).0.mul_by_scalar(&scalar);
            product.plus_point(&pk_multiplied)
        });

    P::pair(signature.0, P::G_2::one_point())
        == P::pair(P::G_1::one_point(), product_of_pks_mul_by_hash)
}

pub fn verify_aggregate_sig_v3<P: Pairing>(
    m_pk_pairs: &[(&[u8], PublicKey<P>)],
    signature: Signature<P>,
) -> bool {
    // check for duplicates
    let ms: Vec<&[u8]> = m_pk_pairs.iter().map(|x| x.0).collect();
    if has_duplicates(ms) {
        return false;
    }

    let (m0, pk0) = &m_pk_pairs[0];
    let scalar0 = scalar_from_message::<P>(m0);
    let mut prod_so_far = pk0.0.mul_by_scalar(&scalar0);
    for i in 1..m_pk_pairs.len() {
        let (m, pk) = &m_pk_pairs[i];
        let scalar = scalar_from_message::<P>(m);
        let pk_mul = pk.0.mul_by_scalar(&scalar);
        prod_so_far = prod_so_far.plus_point(&pk_mul);
    }

    P::pair(signature.0, P::G_2::one_point())
        == P::pair(P::G_1::one_point(), prod_so_far)
}

pub fn verify_aggregate_sig_v4<P: Pairing>(
    m_pk_pairs: &[(&[u8], PublicKey<P>)],
    signature: Signature<P>,
) -> bool {
    // check for duplicates
    let ms: Vec<&[u8]> = m_pk_pairs.iter().map(|x| x.0).collect();
    if has_duplicates(ms) {
        return false;
    }

    let (m0, pk0) = &m_pk_pairs[0];
    let scalar0 = scalar_from_message::<P>(m0);
    let mut prod_so_far = pk0.0.mul_by_scalar(&scalar0);
    for i in 1..m_pk_pairs.len() {
        let (m, pk) = &m_pk_pairs[i];
        let scalar = scalar_from_message::<P>(m);
        let pk_mul = pk.0.mul_by_scalar(&scalar);
        prod_so_far = prod_so_far.plus_point(&pk_mul);
    }

    P::pair(signature.0, P::G_2::one_point())
        == P::pair(P::G_1::one_point(), prod_so_far)
}

fn hash_message(m: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    h.input(m);
    hash.copy_from_slice(h.result().as_slice());
    hash
}

// This is not very efficient - the sorting algorithm can exit as soon as it encounters an equality
// and report that a duplicate indeed exists.
// Consider building hashmap or Btree and exit as soon as a duplicate is seen
pub fn has_duplicates(messages: Vec<&[u8]>) -> bool {
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

    const SIGNERS: usize = 200; // should be around 200

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
    fn test_sign_and_verify_once() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let sk = SecretKey::<Bls12>::generate(&mut rng);
        let pk = PublicKey::from_secret(&sk);

        // should verify correctly
        let m = rng.gen::<[u8; 32]>();
        let signature = sign_message(&sk, &m);
        assert!(verify(&m, &pk, &signature));

        // should not verify!
        let signature = sign_message(&sk, &m);
        let sk2 = SecretKey::<Bls12>::generate(&mut rng);
        let pk2 = PublicKey::from_secret(&sk2);
        assert!(!verify(&m, &pk2, &signature))
    }

    macro_rules! aggregate_sigs {
        ($messages:expr, $sks:expr) => {{
            let mut sig = sign_message(&$sks[0], &$messages[0]);
            for i in 1..$sks.len() {
                let my_sig = sign_message(&$sks[i], &$messages[i]);
                sig = aggregate_sig(my_sig, sig);
            }
            sig
        }};
    }

    #[test]
    fn test_aggregate_sign_and_verify_v1_once() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let (sks, pks) = get_sks_pks!(SIGNERS, rng);
        let ms = get_random_messages!(SIGNERS, rng);
        let sig = aggregate_sigs!(ms, sks);

        let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::new();
        for i in 0..SIGNERS {
            m_pk_pairs.push((&ms[i], pks[i].clone()));
        }
        assert!(verify_aggregate_sig_v1(&m_pk_pairs, sig));
    }

    #[test]
    fn test_aggregate_sign_and_verify_v2_once() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let (sks, pks) = get_sks_pks!(SIGNERS, rng);
        let ms = get_random_messages!(SIGNERS, rng);
        let sig = aggregate_sigs!(ms, sks);

        let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::new();
        for i in 0..SIGNERS {
            m_pk_pairs.push((&ms[i], pks[i].clone()));
        }

        assert!(verify_aggregate_sig_v2(&m_pk_pairs, sig));
    }

    #[test]
    fn test_aggregate_sign_and_verify_v2_mod_once() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let (sks, pks) = get_sks_pks!(SIGNERS, rng);
        let ms = get_random_messages!(SIGNERS, rng);
        let sig = aggregate_sigs!(ms, sks);

        let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::new();
        for i in 0..SIGNERS {
            m_pk_pairs.push((&ms[i], pks[i].clone()));
        }

        assert!(verify_aggregate_sig_v2_mod(&m_pk_pairs, sig));
    }

    #[test]
    fn test_has_duplicates() {
        let mut ms: Vec<[u8; 8]> = (0..SIGNERS).map(|x| x.to_le_bytes()).collect();
        ms[1] = ms[2];

        // build an array of pointers to the messages - not sure how to do it in a prettier way
        let mut ms_pointers: Vec<&[u8]> = Vec::new();
        for i in 0..SIGNERS {
            ms_pointers.push(&ms[i]);
        }
        assert!(has_duplicates(ms_pointers));
    }

    // single case test with 2 messages, for quick testing while developing
    // #[test]
    // fn test_aggregate_sign_and_verify_v1() {
    //     let seed: &[_] = &[1];
    //     let mut rng: StdRng = SeedableRng::from_seed(seed);
    //     let sk1: SecretKey<Bls12> = SecretKey::<Bls12>::generate(&mut rng);
    //     let sk2: SecretKey<Bls12> = SecretKey::<Bls12>::generate(&mut rng);
    //     let pk1: PublicKey<Bls12> = PublicKey::<Bls12>::from_secret(&sk1);
    //     let pk2: PublicKey<Bls12> = PublicKey::<Bls12>::from_secret(&sk2);
    //     let m1 = rng.gen::<[u8; 32]>();
    //     let m2 = rng.gen::<[u8; 32]>();
    //
    //     let sig1 = sign_message(&sk1, &m1);
    //     let aggregate_sig = aggregate_sig(&m2, &sk2, sig1);
    //     assert!(verify_aggregate_sig_v1(
    //         &[(&m1, pk1), (&m2, pk2)],
    //         aggregate_sig
    //     ))
    // }

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
