use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{Curve, Pairing, Value};
use ff::Field;
use id::sigma_protocols::{common::*, dlog::*};
use rand::Rng;
use random_oracle::RandomOracle;
use rayon::iter::*;
use sha2::{digest::Output, Digest, Sha512};

/// Size of the aggregate signature public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 96;
/// Size of the aggregate signature secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;
/// Size of the aggregate signature in bytes.
pub const SIGNATURE_SIZE: usize = 48;

/// A Secret Key is a scalar in the scalarfield of the pairing.
///
/// EQUALITY IS NOT CONSTANT TIME!!! Do not use in production
/// the trait is implemented only for testing purposes
#[derive(Debug, Eq, Serialize)]
pub struct SecretKey<P: Pairing>(P::ScalarField);

impl<P: Pairing> SecretKey<P> {
    pub fn generate<R: Rng>(rng: &mut R) -> SecretKey<P> { SecretKey(P::generate_scalar(rng)) }

    /// Sign a message using the SecretKey
    pub fn sign(&self, m: &[u8]) -> Signature<P> {
        let g1_hash = P::G1::hash_to_group(m);
        let signature = g1_hash.mul_by_scalar(&self.0);
        Signature(signature)
    }

    /// Prove knowledge of the secret key with respect to the challenge given
    /// via the random oracle.
    pub fn prove<R: Rng>(&self, csprng: &mut R, ro: &mut RandomOracle) -> Proof<P> {
        let prover = Dlog {
            public: P::G2::one_point().mul_by_scalar(&self.0),
            coeff:  P::G2::one_point(),
        };
        let secret = DlogSecret {
            secret: Value::new(self.0),
        };
        prove(ro, &prover, secret, csprng)
            .expect("Input-data is valid, so proving should succeed for this dlog proof.")
    }
}

impl<P: Pairing> Clone for SecretKey<P> {
    fn clone(&self) -> Self { SecretKey(self.0) }
}

impl<P: Pairing> Copy for SecretKey<P> {}

/// NOT CONSTANT TIME!!!
/// USE ONLY FOR TESTING!!!
impl<P: Pairing> PartialEq for SecretKey<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

/// A Public Key is a point on the second curve of the pairing
#[derive(Debug, Eq, Serialize, SerdeBase16Serialize)]
pub struct PublicKey<P: Pairing>(P::G2);

impl<P: Pairing> PublicKey<P> {
    /// Derived from a secret key sk by exponentiating the generator of G2 with
    /// sk.
    ///
    /// For now, the generator used is the default generator of the underlying
    /// library however, this should be parametrized in the future
    pub fn from_secret(sk: &SecretKey<P>) -> PublicKey<P> {
        PublicKey(P::G2::one_point().mul_by_scalar(&sk.0))
    }

    /// Verifies a single message and signature pair using this PublicKey by
    /// checking that     pairing(sig, g_2) == pairing(g1_hash(m),
    /// public_key) where g_2 is the generator of G2.
    ///
    /// For now, the generator used is the default generator of the underlying
    /// library however, this should be parametrized in the future
    pub fn verify(&self, m: &[u8], signature: Signature<P>) -> bool {
        let g1_hash = P::G1::hash_to_group(m);
        // compute pairings in parallel
        P::check_pairing_eq(&signature.0, &P::G2::one_point(), &g1_hash, &self.0)
    }

    /// Check proof of knowledge of the secret key with respect to the public
    /// key and the challenge which is given in terms of a random oracle.
    pub fn check_proof(&self, ro: &mut RandomOracle, proof: &Proof<P>) -> bool {
        let verifier = Dlog {
            public: self.0,
            coeff:  P::G2::one_point(),
        };
        verify(ro, &verifier, proof)
    }
}

impl<P: Pairing> Clone for PublicKey<P> {
    fn clone(&self) -> Self { PublicKey(self.0) }
}

impl<P: Pairing> Copy for PublicKey<P> {}

impl<P: Pairing> PartialEq for PublicKey<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

#[derive(Debug, Eq, Serialize)]
pub struct Signature<P: Pairing>(P::G1);

impl<P: Pairing> Signature<P> {
    /// Aggregates this signatures with the given signature.
    pub fn aggregate(&self, to_aggregate: Signature<P>) -> Signature<P> {
        Signature(self.0.plus_point(&to_aggregate.0))
    }

    /// The empty signature is the unit with respect to aggregation,
    /// and can be used as a dummy signature.
    pub fn empty() -> Self { Signature(P::G1::zero_point()) }
}

impl<P: Pairing> Clone for Signature<P> {
    fn clone(&self) -> Self { Signature(self.0) }
}

impl<P: Pairing> Copy for Signature<P> {}

impl<P: Pairing> PartialEq for Signature<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

/// A proof of knowledge of a secretkey
pub type Proof<P> = SigmaProof<Witness<<P as Pairing>::G2>>;

/// Verifies an aggregate signature on pairs `(messages m_i, PK_i)` `for i=1..n`
/// by checking     `pairing(sig, g_2) == product_{i=0}^n (
/// pairing(g1_hash(m_i), PK_i) )` where `g_2` is the generator of G2.
/// Verification returns false if any two messages are not distinct
///
/// For now, the generator used is the default generator of the underlying
/// library however, this should be parametrized in the future
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
            let g1_hash = P::G1::hash_to_group(m);
            let paired = P::pair(&g1_hash, &pk.0);
            let mut p = prod;
            p.mul_assign(&paired);
            p
        })
        .reduce(<P::TargetField as Field>::one, |prod, x| {
            let mut p = prod;
            p.mul_assign(&x);
            p
        });

    P::pair(&signature.0, &P::G2::one_point()) == product
}

/// Verifies an aggregate signature on the same message m under keys PK_i for
/// i=1..n by checking     pairing(sig, g_2) == pairing(g1_hash(m), sum_{i=0}^n
/// (PK_i)) where g_2 is the generator of G2.
///
/// For now, the generator used is the default generator of the underlying
/// library however, this should be parametrized in the future
pub fn verify_aggregate_sig_trusted_keys<P: Pairing>(
    m: &[u8],
    pks: &[PublicKey<P>],
    signature: Signature<P>,
) -> bool {
    // verifying against the empty set of signers always fails
    if pks.is_empty() {
        return false;
    }

    let sum = if pks.len() < 150 {
        pks.iter()
            .fold(P::G2::zero_point(), |s, x| s.plus_point(&x.0))
    } else {
        pks.par_iter()
            .fold(P::G2::zero_point, |s, x| s.plus_point(&x.0))
            .reduce(P::G2::zero_point, |s, x| s.plus_point(&x))
    };

    // compute pairings in parallel
    P::check_pairing_eq(
        &signature.0,
        &P::G2::one_point(),
        &P::G1::hash_to_group(m),
        &sum,
    )
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
fn hash_message(m: &[u8]) -> Output<Sha512> { Sha512::digest(m) }

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};
    use std::convert::TryFrom;

    const SIGNERS: usize = 500;
    const TEST_ITERATIONS: usize = 10;

    // returns a pair of lists (sks, pks), such that sks[i] and pks[i] are
    // corresponding secret and public key
    fn get_sks_pks<P: Pairing>(
        amt: usize,
        rng: &mut StdRng,
    ) -> (Vec<SecretKey<P>>, Vec<PublicKey<P>>) {
        let sks: Vec<SecretKey<P>> = (0..amt).map(|_| SecretKey::<P>::generate(rng)).collect();

        let pks: Vec<PublicKey<P>> = sks.iter().map(PublicKey::<P>::from_secret).collect();
        (sks, pks)
    }

    // returns a list of random bytes (of length 32)
    fn get_random_messages<R: Rng>(amt: usize, rng: &mut R) -> Vec<[u8; 32]> {
        (0..amt).map(|_| rng.gen::<[u8; 32]>()).collect()
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        for _ in 0..TEST_ITERATIONS {
            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let pk = PublicKey::from_secret(&sk);

            // should verify correctly
            let m = rng.gen::<[u8; 32]>();
            let signature = sk.sign(&m);
            assert!(pk.verify(&m, signature));

            // should not verify!
            let signature = sk.sign(&m);
            let sk2 = SecretKey::<Bls12>::generate(&mut rng);
            let pk2 = PublicKey::from_secret(&sk2);
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
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        let (sks, pks) = get_sks_pks(SIGNERS, &mut rng);

        for _ in 0..TEST_ITERATIONS {
            let ms = get_random_messages(SIGNERS, &mut rng);
            let sig = aggregate_sigs!(ms, sks);

            let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::new();
            for i in 0..SIGNERS {
                m_pk_pairs.push((&ms[i], pks[i].clone()));
            }

            // signature should verify
            assert!(verify_aggregate_sig(&m_pk_pairs, sig));

            let (m_, pk_) = m_pk_pairs.pop().unwrap();
            let new_pk = PublicKey::<Bls12>::from_secret(&SecretKey::<Bls12>::generate(&mut rng));
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
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();
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
                &SecretKey::<Bls12>::generate(&mut rng),
            ));
            assert!(!verify_aggregate_sig_trusted_keys(&m, &pks_alt, agg_sig));

            // test that removing a public key makes verification fail
            pks_alt.pop();
            pks_alt.pop();
            assert!(!verify_aggregate_sig_trusted_keys(&m, &pks_alt, agg_sig));

            let agg_sig_alt = Signature(<Bls12 as Pairing>::G1::generate(&mut rng));
            assert!(!verify_aggregate_sig_trusted_keys(&m, &pks, agg_sig_alt));
        }
    }

    #[test]
    fn test_verification_empty_signers() {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();
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
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        for _ in 0..TEST_ITERATIONS {
            let signers: u64 = u64::try_from(SIGNERS)
                .expect("The number of signers should be convertible to u64.");
            let mut ms: Vec<[u8; 8]> = (0..signers).map(|x| x.to_le_bytes()).collect();

            // Make a duplication in the messages
            let random_idx1: usize = rng.gen_range(0, SIGNERS);
            let mut random_idx2: usize = rng.gen_range(0, SIGNERS);
            while random_idx1 == random_idx2 {
                random_idx2 = rng.gen_range(0, SIGNERS)
            }
            ms[random_idx1] = ms[random_idx2];
            let vs: Vec<(&[u8], ())> = ms.iter().map(|x| (&x[..], ())).collect();

            let result = has_duplicates(&vs);
            assert!(result);
        }
    }

    #[test]
    fn test_to_from_bytes_identity() {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        for _ in 0..100 {
            let m = rng.gen::<[u8; 32]>();
            let mut c = Vec::new();
            c.push(rng.gen::<u8>());
            let mut ro = RandomOracle::domain(&c);

            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let pk = PublicKey::<Bls12>::from_secret(&sk);
            let sig = sk.sign(&m);
            let proof = sk.prove(&mut rng, &mut ro.split());

            let sk_from_bytes = serialize_deserialize(&sk);
            let pk_from_bytes = serialize_deserialize(&pk);
            let sig_from_bytes = serialize_deserialize(&sig);
            let proof_from_bytes = serialize_deserialize(&proof);

            let sk_from_bytes = sk_from_bytes.expect("Serialization failed.");
            let pk_from_bytes = pk_from_bytes.expect("Serialization failed.");
            let sig_from_bytes = sig_from_bytes.expect("Serialization failed.");
            let proof_from_bytes = proof_from_bytes.expect("Serialization failed.");

            assert_eq!(sig.0, sig_from_bytes.0);
            assert_eq!(sk.0, sk_from_bytes.0);
            assert_eq!(pk.0, pk_from_bytes.0);
            assert!(pk.check_proof(&mut ro.split(), &proof_from_bytes));
            assert!(pk.verify(&m, sig_from_bytes));
            assert!(pk_from_bytes.verify(&m, sig));
            assert!(pk.check_proof(&mut ro, &proof))
        }
    }

    #[test]
    fn test_to_bytes_correct_length() {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        for _ in 0..100 {
            let m = rng.gen::<[u8; 32]>();
            let mut c = Vec::new();
            c.push(rng.gen::<u8>());
            let mut ro = RandomOracle::domain(&c);

            let sk = SecretKey::<Bls12>::generate(&mut rng);
            let pk = PublicKey::<Bls12>::from_secret(&sk);
            let sig = sk.sign(&m);
            let proof = sk.prove(&mut rng, &mut ro);

            let sk_bytes = to_bytes(&sk);
            let pk_bytes = to_bytes(&pk);
            let sig_bytes = to_bytes(&sig);
            let proof_bytes = to_bytes(&proof);

            assert_eq!(sk_bytes.len(), 32);
            assert_eq!(pk_bytes.len(), 96);
            assert_eq!(sig_bytes.len(), 48);
            assert_eq!(proof_bytes.len(), 64);
        }
    }

    #[test]
    fn test_proof_of_knowledge() {
        let mut csprng = thread_rng();
        for i in 0..100 {
            let n = (i % 32) + 1;
            let mut c1: Vec<u8>;
            let mut c2: Vec<u8>;
            loop {
                c1 = Vec::new();
                c2 = Vec::new();
                for _ in 0..n {
                    c1.push(csprng.gen::<u8>());
                    c2.push(csprng.gen::<u8>());
                }

                if c1 != c2 {
                    break;
                }
            }
            let mut ro1 = RandomOracle::domain(c1);
            let mut ro2 = RandomOracle::domain(c2);

            let sk = SecretKey::<Bls12>::generate(&mut csprng);
            let pk = PublicKey::<Bls12>::from_secret(&sk);
            let proof = sk.prove(&mut csprng, &mut ro1.split());

            assert!(pk.check_proof(&mut ro1.split(), &proof));
            // check that it doesn't verify a proof with the wrong context
            assert!(!(pk.check_proof(&mut ro2, &proof)));
            // check that the proof doesn't work for a different key
            let mut sk2: SecretKey<Bls12>;
            loop {
                sk2 = SecretKey::<Bls12>::generate(&mut csprng);
                if sk != sk2 {
                    break;
                }
            }
            let pk2 = PublicKey::<Bls12>::from_secret(&sk2);
            assert!(!(pk2.check_proof(&mut ro1, &proof)));
        }
    }
}
