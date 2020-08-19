#![allow(non_snake_case)]
use crate::{proofs::enc_trans::*, types::*};
use bulletproofs::range_proof::{
    prove_given_scalars as bulletprove, verify_efficient,
    VerificationError as BulletproofVerificationError,
};
use crypto_common::types::Amount;
use curve_arithmetic::{Curve, Value};
use elgamal::{Cipher, PublicKey, Randomness, SecretKey, ChunkSize};
use id::{
    sigma_protocols::{
        aggregate_dlog::*,
        com_eq::*,
        common::*,
        dlog::{Witness as DlogWitness, *},
    },
    types::GlobalContext,
};
use merlin::Transcript;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness as PedersenRandomness};
use rand::*;
use random_oracle::*;
use std::rc::Rc;

/// First attempt implementing protocol genEncExpInfo documented in the
/// Cryptoprim Bluepaper, maybe without bulletproof part.
#[allow(clippy::many_single_char_names)]
fn gen_enc_exp_info<C: Curve>(
    cmm_key: &CommitmentKey<C>,
    pk: &PublicKey<C>,
    cipher: &[Cipher<C>],
) -> Vec<ComEq<C, C>> {
    let pk_eg = pk.key;
    let mut sigma_protocols = Vec::with_capacity(cipher.len());
    for cipher in cipher {
        let commitment = Commitment(cipher.1);
        let y = cipher.0;
        let cmm_key_comeq = CommitmentKey {
            g: pk_eg,
            h: cmm_key.h,
        };
        let comeq = ComEq {
            commitment,
            y,
            cmm_key: cmm_key_comeq,
            g: cmm_key.g,
        };
        sigma_protocols.push(comeq);
    }
    sigma_protocols
}

/// Implementation of genEncTransProofInfo in the Cryptoprim Bluepaper
pub fn gen_enc_trans_proof_info<C: Curve>(
    pk_sender: &PublicKey<C>,
    pk_receiver: &PublicKey<C>,
    S: &Cipher<C>,
    A: &[Cipher<C>],
    S_prime: &[Cipher<C>],
    h: &C,
) -> EncTrans<C> {
    let sigma_1 = Dlog {
        public: pk_sender.key,
        coeff:  pk_sender.generator,
    };
    // DOCUMENT THIS: It seems that something is missing here, we are not proving
    // that S' + A = S anywhere that I can see.
    let (e1, e2) = (S.0, S.1);
    let elg_dec = AggregateDlog {
        // Elcdec could have its own type instead
        public: e2,
        coeff:  vec![e1, *h], // It is important that we do *not* provide more than 2 elements here
    };
    let sigma_2 = elg_dec;
    let cmm_key = CommitmentKey {
        g: pk_sender.generator,
        h: *h,
    };
    let sigma_3_protocols = gen_enc_exp_info(&cmm_key, pk_receiver, A);
    let sigma_4_protocols = gen_enc_exp_info(&cmm_key, pk_sender, S_prime);
    EncTrans {
        dlog:    sigma_1,
        elg_dec: sigma_2,
        encexp1: sigma_3_protocols,
        encexp2: sigma_4_protocols,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn gen_enc_trans<C: Curve, R: Rng>(
    context: &GlobalContext<C>,
    ro: RandomOracle,
    transcript: &mut Transcript,
    pk_sender: &PublicKey<C>,
    sk_sender: &SecretKey<C>,
    pk_receiver: &PublicKey<C>,
    index: u64,    // indicates which amounts were used
    S: &Cipher<C>, // encryption of the input amount up to the index, combined into one encryption
    s: Amount,     // input amount
    a: Amount,     // amount to send
    csprng: &mut R,
) -> Option<EncryptedAmountTransferData<C>> {
    if s < a {
        return None;
    }

    // For Bulletproofs
    let gens = context.bulletproof_generators();
    let generator = context.encryption_in_exponent_generator();

    let s_prime = u64::from(s) - u64::from(a);
    let s_prime_chunks = CHUNK_SIZE.u64_to_chunks(s_prime);
    let a_chunks = CHUNK_SIZE.u64_to_chunks(u64::from(a));
    let A_enc_randomness = a_chunks
        .iter()
        .map(|&x| {
            pk_receiver.encrypt_exponent_rand_given_generator(
                csprng,
                &Value::<C>::from_u64(x),
                generator,
            )
        })
        .collect::<Vec<_>>();
    let (A, A_rand): (Vec<_>, Vec<_>) = A_enc_randomness.iter().cloned().unzip();
    let S_prime_enc_randomness = s_prime_chunks
        .iter()
        .map(|&x| {
            pk_sender.encrypt_exponent_rand_given_generator(
                csprng,
                &Value::<C>::from_u64(x),
                generator,
            )
        })
        .collect::<Vec<_>>();

    let (S_prime, S_prime_rand): (Vec<_>, Vec<_>) = S_prime_enc_randomness.iter().cloned().unzip();

    let protocol = gen_enc_trans_proof_info(&pk_sender, &pk_receiver, &S, &A, &S_prime, &generator);
    let A_rand_as_value: Vec<Value<_>> = A_rand.iter().map(Randomness::to_value).collect();
    let a_chunks_as_rand: Vec<PedersenRandomness<_>> = a_chunks
        .iter()
        .copied()
        .map(PedersenRandomness::from_u64)
        .collect();
    let S_prime_rand_as_value: Vec<Value<_>> =
        S_prime_rand.iter().map(Randomness::to_value).collect();
    let s_prime_chunks_as_rand: Vec<PedersenRandomness<_>> = s_prime_chunks
        .iter()
        .copied()
        .map(PedersenRandomness::from_u64)
        .collect();
    let secret = EncTransSecret {
        // Bad naming of r_a, a, r_s and s
        dlog_secret: Rc::new(sk_sender.scalar),
        r_a:         a_chunks_as_rand,
        a:           A_rand_as_value,
        r_s:         s_prime_chunks_as_rand,
        s:           S_prime_rand_as_value,
    };
    let sigma_proof = prove(ro.split(), &protocol, secret, csprng)?;
    let cmm_key_bulletproof_a = CommitmentKey {
        g: *generator,
        h: pk_receiver.key,
    };
    let cmm_key_bulletproof_s_prime = CommitmentKey {
        g: *generator,
        h: pk_sender.key,
    };
    let a_chunks_as_scalars: Vec<_> = a_chunks.iter().copied().map(C::scalar_from_u64).collect();
    let A_rand_as_pedrand: Vec<PedersenRandomness<_>> = A_rand
        .iter()
        .map(|x| PedersenRandomness::from_value(&x.to_value()))
        .collect();
    let s_prime_chunks_as_scalars: Vec<_> = s_prime_chunks
        .iter()
        .copied()
        .map(C::scalar_from_u64)
        .collect();
    let S_prime_rand_as_pedrand: Vec<PedersenRandomness<_>> = S_prime_rand
        .iter()
        .map(|x| PedersenRandomness::new(*(x.as_ref())))
        .collect();

    let bulletproof_a = bulletprove(
        transcript,
        csprng,
        32,
        a_chunks.len() as u8,
        &a_chunks_as_scalars,
        &gens,
        &cmm_key_bulletproof_a,
        &A_rand_as_pedrand,
    )?;

    let bulletproof_s_prime = bulletprove(
        transcript,
        csprng,
        32,
        s_prime_chunks.len() as u8,
        &s_prime_chunks_as_scalars,
        &gens,
        &cmm_key_bulletproof_s_prime,
        &S_prime_rand_as_pedrand,
    )?;
    let proof = EncryptedAmountTransferProof {
        accounting: sigma_proof,
        transfer_amount_correct_encryption: bulletproof_a,
        remaining_amount_correct_encryption: bulletproof_s_prime,
    };

    let transfer_amount = EncryptedAmount {
        encryptions: [A[0], A[1]],
    };

    let remaining_amount = EncryptedAmount {
        encryptions: [S_prime[0], S_prime[1]],
    };

    Some(EncryptedAmountTransferData {
        transfer_amount,
        remaining_amount,
        index,
        proof,
    })
}

/// For sending secret balance to public balance
#[allow(clippy::too_many_arguments)]
#[allow(non_snake_case)]
pub fn gen_sec_to_pub_trans<C: Curve, R: Rng>(
    context: &GlobalContext<C>,
    ro: RandomOracle,
    transcript: &mut Transcript,
    pk: &PublicKey<C>, // sender and receiver are the same person
    sk: &SecretKey<C>,
    index: u64,    // indicates which amounts were used
    S: &Cipher<C>, // encryption of the input amount up to the index, combined into one encryption
    s: Amount,     // input amount
    a: Amount,     // amount to send
    csprng: &mut R,
) -> Option<SecToPubAmountTransferData<C>> {
    if s < a {
        return None;
    }

    // For Bulletproofs
    let gens = context.bulletproof_generators();
    let generator = context.encryption_in_exponent_generator();

    let CHUNK_SIZE_ONE : ChunkSize = ChunkSize::SixtyFour;
    let s_prime = s - a;
    let s_prime_chunks = CHUNK_SIZE.u64_to_chunks(s_prime);
    // let a_chunks = CHUNK_SIZE_ONE.u64_to_chunks(a);
    // let A_enc_randomness = a_chunks
    //     .iter()
    //     .map(|&x| {
    //         pk.encrypt_exponent_rand_given_generator(
    //             csprng,
    //             &Value::<C>::from_u64(x),
    //             generator,
    //         )
    //     })
    //     .collect::<Vec<_>>();
    // let (A, A_rand): (Vec<_>, Vec<_>) = A_enc_randomness.iter().cloned().unzip();
    let S_prime_enc_randomness = s_prime_chunks
        .iter()
        .map(|&x| {
            pk.encrypt_exponent_rand_given_generator(
                csprng,
                &Value::<C>::from_u64(x),
                generator,
            )
        })
        .collect::<Vec<_>>();
    let A_dummy_encryption = {
        let ha = generator.mul_by_scalar(&C::scalar_from_u64(a));
        // Cipher(pk.generator, ha)
        Cipher(C::zero_point(), ha)
    };
    let A = vec![A_dummy_encryption];

    let (S_prime, S_prime_rand): (Vec<_>, Vec<_>) = S_prime_enc_randomness.iter().cloned().unzip();
    let protocol = gen_enc_trans_proof_info(&pk, &pk, &S, &A, &S_prime, &generator);
    
    // let A_rand_as_value: Vec<Value<_>> = A_rand.iter().map(Randomness::to_value).collect();
    // let a_chunks_as_rand: Vec<PedersenRandomness<_>> = a_chunks
    //     .iter()
    //     .copied()
    //     .map(PedersenRandomness::from_u64)
    //     .collect();
    let S_prime_rand_as_value: Vec<Value<_>> =
        S_prime_rand.iter().map(Randomness::to_value).collect();
    let s_prime_chunks_as_rand: Vec<PedersenRandomness<_>> = s_prime_chunks
        .iter()
        .copied()
        .map(PedersenRandomness::from_u64)
        .collect();
    // println!("len = {}", a_chunks_as_rand.len());
    let a_chunks_as_rand = vec![PedersenRandomness::from_u64(a)];
    let A_rand_as_value = vec![Value::from_u64(0)];
    let secret = EncTransSecret {
        dlog_secret: Rc::new(sk.scalar),
        r_a:         a_chunks_as_rand,
        a:           A_rand_as_value,
        r_s:         s_prime_chunks_as_rand,
        s:           S_prime_rand_as_value,
    };
    let sigma_proof = prove(ro.split(), &protocol, secret, csprng)?;
    // let cmm_key_bulletproof_a = CommitmentKey {
    //     g: *generator,
    //     h: pk.key,
    // };
    let cmm_key_bulletproof_s_prime = CommitmentKey {
        g: *generator,
        h: pk.key,
    };
    // let a_chunks_as_scalars: Vec<_> = a_chunks.iter().copied().map(C::scalar_from_u64).collect();
    // let A_rand_as_pedrand: Vec<PedersenRandomness<_>> = A_rand
    //     .iter()
    //     .map(|x| PedersenRandomness::from_value(&x.to_value()))
    //     .collect();
    let s_prime_chunks_as_scalars: Vec<_> = s_prime_chunks
        .iter()
        .copied()
        .map(C::scalar_from_u64)
        .collect();
    let S_prime_rand_as_pedrand: Vec<PedersenRandomness<_>> = S_prime_rand
        .iter()
        .map(|x| PedersenRandomness::new(*(x.as_ref())))
        .collect();

    // let bulletproof_a = bulletprove(
    //     transcript,
    //     csprng,
    //     32,
    //     a_chunks.len() as u8,
    //     &a_chunks_as_scalars,
    //     &gens,
    //     &cmm_key_bulletproof_a,
    //     &A_rand_as_pedrand,
    // )?;

    let bulletproof_s_prime = bulletprove(
        transcript,
        csprng,
        32,
        s_prime_chunks.len() as u8,
        &s_prime_chunks_as_scalars,
        &gens,
        &cmm_key_bulletproof_s_prime,
        &S_prime_rand_as_pedrand,
    )?;
    let proof = SecToPubAmountTransferProof {
        accounting: sigma_proof,
        remaining_amount_correct_encryption: bulletproof_s_prime,
    };

    let transfer_amount = a;
    println!("S prime len = {:?}", S_prime.len());

    let remaining_amount = EncryptedAmount {
        encryptions: [S_prime[0], S_prime[1]],
    };

    Some(SecToPubAmountTransferData {
        transfer_amount,
        remaining_amount,
        index,
        proof,
    })
}

/// The verifier does three checks. In case verification fails, it can be useful
/// to know which of the checks led to failure.
#[derive(Debug, PartialEq)]
pub enum VerificationError {
    SigmaProofError,
    /// The first check failed (see function below for what this means)
    FirstBulletproofError(BulletproofVerificationError),
    /// The second check failed.
    SecondBulletproofError(BulletproofVerificationError),
}

#[allow(clippy::too_many_arguments)]
pub fn verify_enc_trans<C: Curve>(
    context: &GlobalContext<C>,
    ro: RandomOracle,
    transcript: &mut Transcript,
    transaction: &EncryptedAmountTransferData<C>,
    pk_sender: &PublicKey<C>,
    pk_receiver: &PublicKey<C>,
    S: &Cipher<C>, // encryption of the amount on the account
) -> Result<(), VerificationError> {
    let generator = context.encryption_in_exponent_generator();
    // For Bulletproofs
    let gens = context.bulletproof_generators();

    let protocol = gen_enc_trans_proof_info(
        &pk_sender,
        &pk_receiver,
        &S,
        &transaction.transfer_amount.as_ref(),
        &transaction.remaining_amount.as_ref(),
        &generator,
    );
    if !verify(ro, &protocol, &transaction.proof.accounting) {
        return Err(VerificationError::SigmaProofError);
    }
    let num_chunks = 64 / usize::from(u8::from(CHUNK_SIZE));
    let commitments_a = {
        let mut commitments_a = Vec::with_capacity(num_chunks);
        let ta: &[Cipher<C>; 2] = transaction.transfer_amount.as_ref();
        for cipher in ta {
            commitments_a.push(Commitment(cipher.1));
        }
        commitments_a
    };

    let commitments_s_prime = {
        let mut commitments_s_prime = Vec::with_capacity(num_chunks);
        let ts_prime: &[Cipher<C>; 2] = transaction.remaining_amount.as_ref();
        for cipher in ts_prime {
            commitments_s_prime.push(Commitment(cipher.1));
        }
        commitments_s_prime
    };

    let cmm_key_bulletproof_a = CommitmentKey {
        g: *generator,
        h: pk_receiver.key,
    };
    let cmm_key_bulletproof_s_prime = CommitmentKey {
        g: *generator,
        h: pk_sender.key,
    };

    let first_bulletproof = verify_efficient(
        transcript,
        32,
        &commitments_a,
        &transaction.proof.transfer_amount_correct_encryption,
        &gens,
        &cmm_key_bulletproof_a,
    );
    if let Err(err) = first_bulletproof {
        return Err(VerificationError::FirstBulletproofError(err));
    }
    let second_bulletproof = verify_efficient(
        transcript,
        32,
        &commitments_s_prime,
        &transaction.proof.remaining_amount_correct_encryption,
        &gens,
        &cmm_key_bulletproof_s_prime,
    );
    if let Err(err) = second_bulletproof {
        return Err(VerificationError::SecondBulletproofError(err));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_sec_to_pub_trans<C: Curve>(
    context: &GlobalContext<C>,
    ro: RandomOracle,
    transcript: &mut Transcript,
    transaction: &SecToPubAmountTransferData<C>,
    pk: &PublicKey<C>,
    S: &Cipher<C>, // encryption of the amount on the account
) -> Result<(), VerificationError> {
    let generator = context.encryption_in_exponent_generator();
    let gens = context.bulletproof_generators();
    // let S_prime = &transaction.remaining_amount;
    let a = transaction.transfer_amount;
    let A_dummy_encryption = {
        let ha = generator.mul_by_scalar(&C::scalar_from_u64(a));
        Cipher(C::zero_point(), ha)
    };
    let A = [A_dummy_encryption];
    
    let protocol = gen_enc_trans_proof_info(
        &pk,
        &pk,
        &S,
        &A,
        &transaction.remaining_amount.as_ref(),
        &generator,
    );
    if !verify(ro, &protocol, &transaction.proof.accounting) {
        return Err(VerificationError::SigmaProofError);
    }
    
    let num_chunks = 64 / usize::from(u8::from(CHUNK_SIZE));

    let commitments_s_prime = {
        let mut commitments_s_prime = Vec::with_capacity(num_chunks);
        let ts_prime: &[Cipher<C>; 2] = transaction.remaining_amount.as_ref();
        for cipher in ts_prime {
            commitments_s_prime.push(Commitment(cipher.1));
        }
        commitments_s_prime
    };
    
    let cmm_key_bulletproof_s_prime = CommitmentKey {
        g: *generator,
        h: pk.key,
    };
    let bulletproof = verify_efficient(
        transcript,
        32,
        &commitments_s_prime,
        &transaction.proof.remaining_amount_correct_encryption,
        &gens,
        &cmm_key_bulletproof_s_prime,
    );
    if let Err(err) = bulletproof {
        // Maybe introduce yet another error type for this type of transaction
        return Err(VerificationError::SecondBulletproofError(err));
    }
    Ok(())
}

struct DlogEqual<C: Curve> {
    dlog1: Dlog<C>,
    dlog2: Dlog<C>,
}

impl<C: Curve> SigmaProtocol for DlogEqual<C> {
    type CommitMessage = (C, C);
    type ProtocolChallenge = C::Scalar;
    type ProverState = C::Scalar;
    type ProverWitness = DlogWitness<C>;
    type SecretData = DlogSecret<C>;

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        let ro1 = self.dlog1.public(ro);
        self.dlog2.public(ro1)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let rand_scalar = C::generate_non_zero_scalar(csprng);
        let randomized_point_1 = self.dlog1.coeff.mul_by_scalar(&rand_scalar);
        let randomized_point_2 = self.dlog2.coeff.mul_by_scalar(&rand_scalar);
        let commit = (randomized_point_1, randomized_point_2);
        Some((commit, rand_scalar))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let w1 = self.dlog1.generate_witness(secret, state, &challenge)?;
        Some(w1)
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let p1 = self.dlog1.extract_point(&challenge, &witness)?;
        let p2 = self.dlog2.extract_point(&challenge, &witness)?;
        Some((p1, p2))
    }

    // #[cfg(test)]
    // fn with_valid_data<R: rand::Rng>(
    //     data_size: usize,
    //     csprng: &mut R,
    //     f: impl FnOnce(Self, Self::SecretData, &mut R) -> (),
    // ) {
    //     ()
    // }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proofs::dlogaggequal::*;
    use curve_arithmetic::multiexp;
    use ff::PrimeField;
    use pairing::bls12_381::{Fr, G1};
    // use rand::{rngs::ThreadRng, Rng};

    type SomeCurve = G1;
    // Copied from common.rs in sigma_protocols since apparently it is not available
    pub fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
        // length of the challenge
        let l = csprng.gen_range(0, 1000);
        let mut challenge_prefix = vec![0; l];
        for v in challenge_prefix.iter_mut() {
            *v = csprng.gen();
        }
        challenge_prefix
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_gen_eq() {
        let mut csprng = thread_rng();
        let x = Fr::from_str("3").unwrap();
        let x_secret = Value::<G1>::new(x);
        let g1 = G1::generate(&mut csprng);
        let g2 = G1::generate(&mut csprng);
        let g1x = g1.mul_by_scalar(&x);
        let g2x = g2.mul_by_scalar(&x);
        let dlog1 = Dlog {
            public: g1x,
            coeff:  g1,
        };
        let dlog2 = Dlog {
            public: g2x,
            coeff:  g2,
        };
        let equal = DlogEqual { dlog1, dlog2 };
        let secret = DlogSecret { secret: x_secret };
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        let proof = prove(ro.split(), &equal, secret, &mut csprng).unwrap();
        assert!(verify(ro, &equal, &proof));
    }

    #[test]
    fn test_dlog_agg_eq() {
        let mut csprng = thread_rng();
        let x = Fr::from_str("3").unwrap();
        let x1 = Fr::from_str("5").unwrap();
        let x2 = Fr::from_str("7").unwrap();
        let y1 = Fr::from_str("70").unwrap();
        let y2 = Fr::from_str("75").unwrap();
        let g = G1::generate(&mut csprng);
        let g1 = G1::generate(&mut csprng);
        let h1 = G1::generate(&mut csprng);
        let f1 = G1::generate(&mut csprng);
        let g2 = G1::generate(&mut csprng);
        let h2 = G1::generate(&mut csprng);
        let f2 = G1::generate(&mut csprng);
        let gx = g.mul_by_scalar(&x);
        let dlog = Dlog {
            public: gx,
            coeff:  g,
        };
        let g1xh1x1f1y1 = multiexp(&[g1, h1, f1], &[x, x1, y1]);
        let g2xh2x2f2y2 = multiexp(&[g2, h2, f2], &[x, x2, y2]);
        let agg1 = AggregateDlog {
            public: g1xh1x1f1y1,
            coeff:  vec![g1, h1, f1],
        };
        let agg2 = AggregateDlog {
            public: g2xh2x2f2y2,
            coeff:  vec![g2, h2, f2],
        };
        let protocol = DlogAndAggregateDlogsEqual {
            dlog,
            aggregate_dlogs: vec![agg1, agg2],
        };
        let secret = (Rc::new(x), vec![vec![Rc::new(x1), Rc::new(y1)], vec![
            Rc::new(x2),
            Rc::new(y2),
        ]]);
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        let proof = prove(ro.split(), &protocol, secret, &mut csprng).unwrap();
        assert!(verify(ro, &protocol, &proof));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_enc_trans() {
        let mut csprng = thread_rng();
        let sk_sender: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
        let pk_sender = PublicKey::from(&sk_sender);
        let sk_receiver: SecretKey<G1> = SecretKey::generate(&pk_sender.generator, &mut csprng);
        let pk_receiver = PublicKey::from(&sk_receiver);
        let s = csprng.gen(); // amount on account.

        let a = csprng.gen_range(0, s); // amount to send

        let m = 2; // 2 chunks
        let n = 32;
        let nm = n * m;

        let context = GlobalContext::<SomeCurve>::generate_size(nm);
        let generator = context.encryption_in_exponent_generator(); // h
        let s_value = Value::from_u64(s);
        let S = pk_sender.encrypt_exponent_given_generator(&mut csprng, &s_value, generator);

        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        // Somewhere there should be some kind of connection
        // between the transcript and the RO,
        // maybe inside the functions used below?

        let mut transcript = Transcript::new(&[]);
        let index = csprng.gen(); // index is only important for on-chain stuff, not for proofs.
        let transaction = gen_enc_trans(
            &context,
            ro.split(),
            &mut transcript,
            &pk_sender,
            &sk_sender,
            &pk_receiver,
            index,
            &S,
            Amount::from(s),
            Amount::from(a),
            &mut csprng,
        )
        .expect("Could not produce proof.");

        let mut transcript = Transcript::new(&[]);

        assert_eq!(
            verify_enc_trans(
                &context,
                ro,
                &mut transcript,
                &transaction,
                &pk_sender,
                &pk_receiver,
                &S,
            ),
            Ok(())
        )
    }

    
    #[allow(non_snake_case)]
    #[test]
    fn test_sec_to_pub() {
        let mut csprng = thread_rng();
        let sk: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
        let pk = PublicKey::from(&sk);
        let s = csprng.gen(); // amount on account.

        let a = csprng.gen_range(0, s); // amount to send

        let m = 2; // 2 chunks
        let n = 32;
        let nm = n * m;

        let context = GlobalContext::<SomeCurve>::generate_size(nm, &mut csprng);
        let generator = context.encryption_in_exponent_generator(); // h
        let s_value = Value::from_u64(s);
        let S = pk.encrypt_exponent_given_generator(&mut csprng, &s_value, generator);

        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        // Somewhere there should be some kind of connection
        // between the transcript and the RO,
        // maybe inside the functions used below?

        let mut transcript = Transcript::new(&[]);
        let index = csprng.gen(); // index is only important for on-chain stuff, not for proofs.
        let transaction = gen_sec_to_pub_trans(
            &context,
            ro.split(),
            &mut transcript,
            &pk,
            &sk,
            index,
            &S,
            s,
            a,
            &mut csprng,
        ).unwrap();
        let mut transcript = Transcript::new(&[]);

        assert_eq!(
            verify_sec_to_pub_trans(
                &context,
                ro,
                &mut transcript,
                &transaction,
                &pk,
                &S,
            ),
            Ok(())
        )
    }
}
