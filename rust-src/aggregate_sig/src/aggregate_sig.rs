use crate::errors::AggregateSigError;
use curve_arithmetic::{Curve, Pairing};
use ff::Field;
use generic_array::GenericArray;
use rand::Rng;
use rayon::{iter::*, join};
use sha2::{Digest, Sha512};
use std::io::Cursor;

pub const PUBLIC_KEY_SIZE: usize = 96;
pub const SECRET_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 48;

// A Secret Key is a scalar in the scalarfield of the pairing.
//
// EQUALITY IS NOT CONSTANT TIME!!! Do not use in production
// the trait is implemented only for testing purposes
#[derive(Debug, Eq)]
pub struct SecretKey<P: Pairing>(P::ScalarField);

impl<P: Pairing> SecretKey<P> {
    pub fn generate<R: Rng>(rng: &mut R) -> SecretKey<P> { SecretKey(P::generate_scalar(rng)) }

    pub fn from_bytes(b: &mut Cursor<&[u8]>) -> Result<SecretKey<P>, AggregateSigError> {
        let s = P::bytes_to_scalar(b)?;
        Ok(SecretKey(s))
    }

    pub fn to_bytes(&self) -> Box<[u8]> { P::scalar_to_bytes(&self.0) }

    // Sign a message using the SecretKey
    pub fn sign(&self, m: &[u8]) -> Signature<P> {
        let g1_hash = P::G_1::hash_to_group(m);
        let signature = g1_hash.mul_by_scalar(&self.0);
        Signature(signature)
    }
}

impl<P: Pairing> Clone for SecretKey<P> {
    fn clone(&self) -> Self { SecretKey(self.0) }
}

impl<P: Pairing> Copy for SecretKey<P> {}

// NOT CONSTANT TIME!!!
// USE ONLY FOR TESTING!!!
impl<P: Pairing> PartialEq for SecretKey<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

// A Public Key is a point on the second curve of the pairing
#[derive(Debug, Eq)]
pub struct PublicKey<P: Pairing>(P::G_2);

impl<P: Pairing> PublicKey<P> {
    // Derived from a secret key sk by exponentiating the generator of G2 with sk.
    //
    // For now, the generator used is the default generator of the underlying
    // library however, this should be parametrized in the future
    pub fn from_secret(sk: SecretKey<P>) -> PublicKey<P> {
        PublicKey(P::G_2::one_point().mul_by_scalar(&sk.0))
    }

    // Verifies a single message and signature pair using this PublicKey by checking
    // that     pairing(sig, g_2) == pairing(g1_hash(m), public_key)
    // where g_2 is the generator of G2.
    //
    // For now, the generator used is the default generator of the underlying
    // library however, this should be parametrized in the future
    pub fn verify(&self, m: &[u8], signature: Signature<P>) -> bool {
        let g1_hash = P::G_1::hash_to_group(m);
        // compute pairings in parallel
        let (pair1, pair2): (P::TargetField, P::TargetField) = join(
            || P::pair(signature.0, P::G_2::one_point()),
            || P::pair(g1_hash, self.0),
        );
        pair1 == pair2
    }

    pub fn from_bytes(b: &mut Cursor<&[u8]>) -> Result<PublicKey<P>, AggregateSigError> {
        let point = P::G_2::bytes_to_curve(b)?;
        Ok(PublicKey(point))
    }

    pub fn to_bytes(&self) -> Box<[u8]> { P::G_2::curve_to_bytes(&self.0) }
}

impl<P: Pairing> Clone for PublicKey<P> {
    fn clone(&self) -> Self { PublicKey(self.0) }
}

impl<P: Pairing> Copy for PublicKey<P> {}

impl<P: Pairing> PartialEq for PublicKey<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

#[derive(Debug, Eq)]
pub struct Signature<P: Pairing>(P::G_1);

impl<P: Pairing> Signature<P> {
    // Aggregates this signatures with the given signature.
    pub fn aggregate(&self, to_aggregate: Signature<P>) -> Signature<P> {
        Signature(self.0.plus_point(&to_aggregate.0))
    }

    pub fn from_bytes(b: &mut Cursor<&[u8]>) -> Result<Signature<P>, AggregateSigError> {
        let point = P::G_1::bytes_to_curve(b)?;
        Ok(Signature(point))
    }

    // Only used for creating a dummy signature for the genesis block
    pub(crate) fn empty() -> Self { Signature(P::G_1::one_point()) }

    pub fn to_bytes(&self) -> Box<[u8]> { P::G_1::curve_to_bytes(&self.0) }
}

impl<P: Pairing> Clone for Signature<P> {
    fn clone(&self) -> Self { Signature(self.0) }
}

impl<P: Pairing> Copy for Signature<P> {}

impl<P: Pairing> PartialEq for Signature<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

// Verifies an aggregate signature on pairs (messages m_i, PK_i) for i=1..n by
// checking     pairing(sig, g_2) == product_{i=0}^n ( pairing(g1_hash(m_i),
// PK_i) ) where g_2 is the generator of G2.
// Verification returns false if any two messages are not distinct
//
// For now, the generator used is the default generator of the underlying
// library however, this should be parametrized in the future
pub fn verify_aggregate_sig<P: Pairing>(
    m_pk_pairs: &[(&[u8], PublicKey<P>)],
    signature: Signature<P>,
) -> bool {
    // Check for duplicates in messages. Reject if any
    if has_duplicates(m_pk_pairs) {
        return false;
    }
    // verifying against the empty set of signers always fails
    if m_pk_pairs.is_empty() {
        return false;
    }

    let product = m_pk_pairs
        .par_iter()
        .fold(<P::TargetField as Field>::one, |prod, (m, pk)| {
            let g1_hash = P::G_1::hash_to_group(m);
            let paired = P::pair(g1_hash, pk.0);
            let mut p = prod;
            p.mul_assign(&paired);
            p
        })
        .reduce(<P::TargetField as Field>::one, |prod, x| {
            let mut p = prod;
            p.mul_assign(&x);
            p
        });

    P::pair(signature.0, P::G_2::one_point()) == product
}

// Verifies an aggregate signature on the same message m under keys PK_i for
// i=1..n by checking     pairing(sig, g_2) == pairing(g1_hash(m), sum_{i=0}^n
// (PK_i)) where g_2 is the generator of G2.
//
// For now, the generator used is the default generator of the underlying
// library however, this should be parametrized in the future
pub fn verify_aggregate_sig_trusted_keys<P: Pairing>(
    m: &[u8],
    pks: &[PublicKey<P>],
    signature: Signature<P>,
) -> bool {
    // verifying against the empty set of signers always fails
    if pks.is_empty() {
        return false;
    }

    let sum = pks
        .par_iter()
        .fold(P::G_2::zero_point, |sum, x| sum.plus_point(&x.0))
        .reduce(P::G_2::zero_point, |sum, x| sum.plus_point(&x));

    // compute pairings in parallel
    let (pair1, pair2): (P::TargetField, P::TargetField) = join(
        || P::pair(signature.0, P::G_2::one_point()),
        || P::pair(P::G_1::hash_to_group(m), sum),
    );
    pair1 == pair2
}

// Checks for duplicates in a list of messages
// This is not very efficient - the sorting algorithm can exit as soon as it
// encounters an equality and report that a duplicate indeed exists.
// Consider building hashmap or Btree and exit as soon as a duplicate is seen
fn has_duplicates<T>(messages: &[(&[u8], T)]) -> bool {
    let mut message_hashes: Vec<_> = messages.iter().map(|x| hash_message(x.0)).collect();
    message_hashes.sort_unstable();
    for i in 1..message_hashes.len() {
        if message_hashes[i - 1] == message_hashes[i] {
            return true;
        }
    }
    false
}

// hashes a message using Sha512
fn hash_message(m: &[u8]) -> GenericArray<u8, <Sha512 as Digest>::OutputSize> {
    let mut h = Sha512::new();
    h.input(m);
    h.result()
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, StdRng};

    const SIGNERS: usize = 500;
    const TEST_ITERATIONS: usize = 10;

    // returns a pair of lists (sks, pks), such that sks[i] and pks[i] are
    // corresponding secret and public key
    fn get_sks_pks<P: Pairing>(
        amt: usize,
        rng: &mut StdRng,
    ) -> (Vec<SecretKey<P>>, Vec<PublicKey<P>>) {
        let sks: Vec<SecretKey<P>> = (0..amt).map(|_| SecretKey::<P>::generate(rng)).collect();

        let pks: Vec<PublicKey<P>> = sks
            .iter()
            .map(|x| PublicKey::<P>::from_secret(*x))
            .collect();
        (sks, pks)
    }

    // returns a list of random bytes (of length 32)
    fn get_random_messages<R: Rng>(amt: usize, rng: &mut R) -> Vec<[u8; 32]> {
        (0..amt).map(|_| rng.gen::<[u8; 32]>()).collect()
    }

    #[test]
    fn test_sign_and_verify() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        for _ in 0..TEST_ITERATIONS {
            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let pk = PublicKey::from_secret(sk);

            // should verify correctly
            let m = rng.gen::<[u8; 32]>();
            let signature = sk.sign(&m);
            assert!(pk.verify(&m, signature));

            // should not verify!
            let signature = sk.sign(&m);
            let sk2 = SecretKey::<Bls12>::generate(&mut rng);
            let pk2 = PublicKey::from_secret(sk2);
            assert!(!pk2.verify(&m, signature))
        }
    }

    macro_rules! aggregate_sigs {
        ($messages:expr, $sks:expr) => {{
            let mut sig = $sks[0].sign(&$messages[0]);
            for i in 1..$sks.len() {
                let my_sig = $sks[i].sign(&$messages[i]);
                sig = sig.aggregate(my_sig);
            }
            sig
        }};
    }

    #[test]
    fn test_verify_aggregate_sig() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let (sks, pks) = get_sks_pks(SIGNERS, &mut rng);

        for _ in 0..TEST_ITERATIONS {
            let ms = get_random_messages(SIGNERS, &mut rng);
            let sig = aggregate_sigs!(ms, sks);

            let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::new();
            for i in 0..SIGNERS {
                let idx = i as usize;
                m_pk_pairs.push((&ms[idx], pks[idx].clone()));
            }

            // signature should verify
            assert!(verify_aggregate_sig(&m_pk_pairs, sig));

            let (m_, pk_) = m_pk_pairs.pop().unwrap();
            let new_pk = PublicKey::<Bls12>::from_secret(SecretKey::<Bls12>::generate(&mut rng));
            m_pk_pairs.push((m_, new_pk));

            // altering a public key should make verification fail
            assert!(!verify_aggregate_sig(&m_pk_pairs, sig));

            let new_m: [u8; 32] = rng.gen::<[u8; 32]>();
            m_pk_pairs.pop();
            m_pk_pairs.push((&new_m, pk_));

            // altering a message should make verification fail
            assert!(!verify_aggregate_sig(&m_pk_pairs, sig));
        }
    }

    #[test]
    fn test_verify_aggregate_sig_trusted_keys() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        for _ in 0..TEST_ITERATIONS {
            let (sks, pks) = get_sks_pks(SIGNERS, &mut rng);
            let m: [u8; 32] = rng.gen::<[u8; 32]>();
            let sigs: Vec<Signature<Bls12>> = sks.iter().map(|sk| sk.sign(&m)).collect();
            let mut agg_sig = sigs[0].clone();
            sigs.iter().skip(1).for_each(|x| {
                agg_sig = agg_sig.aggregate(*x);
            });

            assert!(verify_aggregate_sig_trusted_keys(&m, &pks, agg_sig));

            // test changing message makes verification fails
            let m_alt: [u8; 32] = rng.gen::<[u8; 32]>();
            assert!(!verify_aggregate_sig_trusted_keys(&m_alt, &pks, agg_sig));

            // test that adding or removing a public key makes verification fail
            let mut pks_alt = pks.clone();
            pks_alt.push(PublicKey::<Bls12>::from_secret(
                SecretKey::<Bls12>::generate(&mut rng),
            ));
            assert!(!verify_aggregate_sig_trusted_keys(&m, &pks_alt, agg_sig));

            // test that removing a public key makes verification fail
            pks_alt.pop();
            pks_alt.pop();
            assert!(!verify_aggregate_sig_trusted_keys(&m, &pks_alt, agg_sig));

            let agg_sig_alt = Signature(<Bls12 as Pairing>::G_1::generate(&mut rng));
            assert!(!verify_aggregate_sig_trusted_keys(&m, &pks, agg_sig_alt));
        }
    }

    #[test]
    fn test_verification_empty_signers() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        for _ in 0..TEST_ITERATIONS {
            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let m: [u8; 32] = rng.gen::<[u8; 32]>();
            let sig = sk.sign(&m);

            assert!(!verify_aggregate_sig(&[], sig));
            assert!(!verify_aggregate_sig_trusted_keys(&m, &[], sig));
        }
    }

    #[test]
    fn test_has_duplicates() {
        use std::convert::TryFrom;

        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        for _ in 0..TEST_ITERATIONS {
            let signers: u64 = u64::try_from(SIGNERS)
                .expect("The number of signers should be convertible to u64.");
            let mut ms: Vec<[u8; 8]> = (0..signers).map(|x| x.to_le_bytes()).collect();

            // Make a duplication in the messages
            let random_idx1: usize = rng.gen_range(0, SIGNERS);
            let mut random_idx2: usize = rng.gen_range(0, SIGNERS);
            while random_idx1 == random_idx2 {
                random_idx2 = rng.gen_range(0, SIGNERS) as usize
            }
            ms[random_idx1] = ms[random_idx2];
            let vs: Vec<(&[u8], ())> = ms.iter().map(|x| (&x[..], ())).collect();

            let result = has_duplicates(&vs);
            assert!(result);
        }
    }

    #[test]
    fn test_to_from_bytes_identity() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        for _ in 0..1000 {
            let m = rng.gen::<[u8; 32]>();
            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let pk = PublicKey::<Bls12>::from_secret(sk);
            let sig = sk.sign(&m);
            let sk_bytes = sk.to_bytes();
            let pk_bytes = pk.to_bytes();
            let sig_bytes = sig.to_bytes();
            let sk_from_bytes =
                SecretKey::<Bls12>::from_bytes(&mut Cursor::new(&sk_bytes)).unwrap();
            let pk_from_bytes =
                PublicKey::<Bls12>::from_bytes(&mut Cursor::new(&pk_bytes)).unwrap();
            let sig_from_bytes =
                Signature::<Bls12>::from_bytes(&mut Cursor::new(&sig_bytes)).unwrap();

            assert_eq!(sig.0, sig_from_bytes.0);
            assert_eq!(sk.0, sk_from_bytes.0);
            assert_eq!(pk.0, pk_from_bytes.0);
            assert!(pk.verify(&m, sig_from_bytes));
            assert!(pk_from_bytes.verify(&m, sig_from_bytes));
        }
    }

    #[test]
    fn test_to_bytes_correct_length() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        for _ in 0..1000 {
            let m = rng.gen::<[u8; 32]>();
            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let pk = PublicKey::<Bls12>::from_secret(sk);
            let sig = sk.sign(&m);

            let sk_bytes = sk.to_bytes();
            let pk_bytes = pk.to_bytes();
            let sig_bytes = sig.to_bytes();

            assert_eq!(sk_bytes.len(), 32);
            assert_eq!(pk_bytes.len(), 96);
            assert_eq!(sig_bytes.len(), 48);
        }
    }
}
