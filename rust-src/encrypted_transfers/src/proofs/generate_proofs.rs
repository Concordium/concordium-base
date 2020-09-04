#![allow(non_snake_case)]
use crate::{proofs::enc_trans::*, types::*};
use bulletproofs::range_proof::{
    prove_given_scalars as bulletprove, verify_efficient,
    VerificationError as BulletproofVerificationError,
};
use crypto_common::{to_bytes, types::Amount};
use curve_arithmetic::{Curve, Value};
use elgamal::{Cipher, PublicKey, Randomness, SecretKey};
use id::{
    sigma_protocols::{com_eq::*, common::*, dlog::*},
    types::GlobalContext,
};
use merlin::Transcript;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness as PedersenRandomness};
use rand::*;
use random_oracle::*;
use std::rc::Rc;

/// This function is an implementation of the genEncExpInfo documented in the
/// Cryptoprim Bluepaper without bulletproof part.
/// It produces a list of ComEq sigmaprotocols, i.e. it can be used to
/// prove knowledge of x_i and r_i such that
/// c_{i,1} = g^{r_i}, c_{i,2} = h^{x_i} pk_receiver^{r_i} for all i.
/// It is meant as helper function to produce what is for the
/// fields encexp1 and encexp2 in the EncTrans struct.
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
/// It produces a sigma protocol of type EncTrans (see enc_trans.rs)
/// Here, both A and S_prime are encrypted amounts that are encrypted
/// in chunks in the exponent, i.e. A is of the form (A_1, ..., A_t)
/// where A_i = (g^r_i, h^a_i pk_receiver^r_i) =: (c_{i,1}, c_{i,2}),
/// and where a_i is the i'th chunk of the amount that A is an encryption of.
/// Similarly, S_prime of the form (S_1', ..., S_(t')'), where
/// S_i' = (g^r_i', h^s_i' pk_sender^r_i') =: (d_{i,1}, d_{i,2})
pub fn gen_enc_trans_proof_info<C: Curve>(
    pk_sender: &PublicKey<C>,
    pk_receiver: &PublicKey<C>,
    S: &Cipher<C>,
    A: &[Cipher<C>],
    S_prime: &[Cipher<C>],
    h: &C,
) -> EncTrans<C> {
    // Sigma protocol for prooving knowledge of sk
    // such that
    // pk_sender = g^sk
    let sigma_1 = Dlog {
        public: pk_sender.key,
        coeff:  pk_sender.generator,
    };

    // DOCUMENT THIS: It seems that something is missing here, we are not proving
    // that S' + A = S anywhere that I can see.
    // UPDATE: are the comments below sufficient for documenting this?

    // ElgDec is used to prove knowledge of sk and s such that
    // pk_sender = g^sk, S_2 = S_1^sk h^s
    let (e1, e2) = (S.0, S.1);
    let elg_dec = ElgDec {
        public: e2,
        coeff:  [e1, *h],
    };
    let sigma_2 = elg_dec;
    let cmm_key = CommitmentKey {
        g: pk_sender.generator,
        h: *h,
    };
    // Sigma protocol for proving knowledge of a_i and r_i
    // such that
    // c_{i,1} = g^{r_i}, c_{i,2} = h^{a_i} pk_receiver^{r_i} for all i
    let sigma_3_protocols = gen_enc_exp_info(&cmm_key, pk_receiver, A);
    // Sigma protocol for proving knowledge of a_i and r_i
    // such that
    // d_{i,1} = g^{r_i'}, d_{i,2} = h^{s_i'} pk_sender^{r_i'} for all i
    let sigma_4_protocols = gen_enc_exp_info(&cmm_key, pk_sender, S_prime);
    // The EncTrans implements the SigmaProtocol trait, and by
    // its implementation it is guaranteed that the secret
    // sk in the dlog, and the secret sk in elg_dec are the same,
    // while it is also guaranteed that the secret s in elg_dec
    // is equal to \sum_{j=1}^t 2^{(chunk_size)*(j-1)} a_j
    //            +\sum_{j=1}^(t') 2^{(chunk_size)*(j-1)} s_j'
    EncTrans {
        dlog:    sigma_1,
        elg_dec: sigma_2,
        encexp1: sigma_3_protocols,
        encexp2: sigma_4_protocols,
    }
}

/// This function produces transfer data containing
/// a proof that an encrypted transfer was done correctly
/// The arguments are
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - a random oracle needed for the sigma protocol
/// - a transcript for Bulletproofs
/// - public key and secret key of sender
/// - public key of receiver
/// - index indicating which amounts where used
/// - S - encryption of the input amount up to the index, combined into one
///   encryption
/// - s - input amount
/// - a - amount to send
/// The proof contained in the transfer data produced
/// by this function is a combination a proof produced by the
/// EncTrans sigma protocol and a rangeproof (Bulletproofs), i.e.
/// additonally showing that all a_j and s_j' are in [0, 2^chunk_size)
/// It returns None if s < a or if it fails to produce one of the bulletproofs.
#[allow(clippy::too_many_arguments)]
pub fn gen_enc_trans<C: Curve, R: Rng>(
    context: &GlobalContext<C>,
    ro: RandomOracle,
    transcript: &mut Transcript,
    pk_sender: &PublicKey<C>,
    sk_sender: &SecretKey<C>,
    pk_receiver: &PublicKey<C>,
    index: u64,
    S: &Cipher<C>,
    s: Amount,
    a: Amount,
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
    transcript.append_message(b"sigmaproof", &to_bytes(&sigma_proof));
    let bulletproof_a = bulletprove(
        transcript,
        csprng,
        u8::from(CHUNK_SIZE),
        a_chunks.len() as u8,
        &a_chunks_as_scalars,
        &gens,
        &cmm_key_bulletproof_a,
        &A_rand_as_pedrand,
    )?;

    let bulletproof_s_prime = bulletprove(
        transcript,
        csprng,
        u8::from(CHUNK_SIZE),
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
/// This function produces transfer data containing
/// a proof that a secret to public balance transfer was done correctly
/// The arguments are
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - a random oracle needed for the sigma protocol
/// - a transcript for Bulletproofs
/// - public key and secret key of sender (who is also the receiver)
/// - index indicating which amounts where used
/// - S - encryption of the input amount up to the index, combined into one
///   encryption
/// - s - input amount
/// - a - amount to send
/// The proof contained in the transfer data produced
/// by this function is a combination a proof produced by the
/// EncTrans sigma protocol and a rangeproof (Bulletproofs), i.e.
/// additonally showing that all s_j' are in [0, 2^chunk_size).
/// Here, the A that is given to gen_enc_trans_proof_info is an encryption
/// of a with randomness 0, in one chunk. The produced EncTrans is then used to
/// prove that s = a + \sum_{j=1}^(t') 2^{(chunk_size)*(j-1)} s_j', where
/// the s_j' denote the chunks of s' := s-a.
/// It returns None if s < a or if it fails to produce the bulletproofs.
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

    let gens = context.bulletproof_generators();
    let generator = context.encryption_in_exponent_generator();
    let s_prime = u64::from(s) - u64::from(a);
    let s_prime_chunks = CHUNK_SIZE.u64_to_chunks(s_prime);
    let S_prime_enc_randomness = s_prime_chunks
        .iter()
        .map(|&x| {
            pk.encrypt_exponent_rand_given_generator(csprng, &Value::<C>::from_u64(x), generator)
        })
        .collect::<Vec<_>>();
    let A_dummy_encryption = {
        let ha = generator.mul_by_scalar(&C::scalar_from_u64(u64::from(a)));
        Cipher(C::zero_point(), ha)
    };
    let A = vec![A_dummy_encryption];

    let (S_prime, S_prime_rand): (Vec<_>, Vec<_>) = S_prime_enc_randomness.iter().cloned().unzip();
    let protocol = gen_enc_trans_proof_info(&pk, &pk, &S, &A, &S_prime, &generator);
    let S_prime_rand_as_value: Vec<Value<_>> =
        S_prime_rand.iter().map(Randomness::to_value).collect();
    let s_prime_chunks_as_rand: Vec<PedersenRandomness<_>> = s_prime_chunks
        .iter()
        .copied()
        .map(PedersenRandomness::from_u64)
        .collect();
    let a_chunks_as_rand = vec![PedersenRandomness::from_u64(u64::from(a))];
    let A_rand_as_value = vec![Value::from_u64(0)];
    let secret = EncTransSecret {
        dlog_secret: Rc::new(sk.scalar),
        r_a:         a_chunks_as_rand,
        a:           A_rand_as_value,
        r_s:         s_prime_chunks_as_rand,
        s:           S_prime_rand_as_value,
    };
    let sigma_proof = prove(ro.split(), &protocol, secret, csprng)?;
    let cmm_key_bulletproof_s_prime = CommitmentKey {
        g: *generator,
        h: pk.key,
    };
    let s_prime_chunks_as_scalars: Vec<_> = s_prime_chunks
        .iter()
        .copied()
        .map(C::scalar_from_u64)
        .collect();
    let S_prime_rand_as_pedrand: Vec<PedersenRandomness<_>> = S_prime_rand
        .iter()
        .map(|x| PedersenRandomness::new(*(x.as_ref())))
        .collect();

    let bulletproof_s_prime = bulletprove(
        transcript,
        csprng,
        u8::from(CHUNK_SIZE),
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

/// This function is for verifying that an encrypted transfer
/// has been done corretly.
/// The arguments are
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - a random oracle needed for the sigma protocol
/// - a transcript for Bulletproofs
/// - a transaction containing a proof
/// - public keys of both sender and receiver
/// - S - Encryption of amount on account
/// It either returns Ok() indicating that the transfer has been done
/// correctly or a VerificationError indicating what failed (the EncTrans
/// protocol or one of the bulletproofs)
#[allow(clippy::too_many_arguments)]
pub fn verify_enc_trans<C: Curve>(
    context: &GlobalContext<C>,
    ro: RandomOracle,
    transcript: &mut Transcript,
    transaction: &EncryptedAmountTransferData<C>,
    pk_sender: &PublicKey<C>,
    pk_receiver: &PublicKey<C>,
    S: &Cipher<C>,
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
    transcript.append_message(b"sigmaproof", &to_bytes(&transaction.proof.accounting));
    let first_bulletproof = verify_efficient(
        transcript,
        u8::from(CHUNK_SIZE),
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
        u8::from(CHUNK_SIZE),
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

/// This function is for verifying that an encrypted transfer
/// has been done corretly.
/// The arguments are
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - a random oracle needed for the sigma protocol
/// - a transcript for Bulletproofs
/// - a transaction containing a proof
/// - public key of both sender (who is also the receiver)
/// - S - Encryption of amount on account
/// It either returns Ok() indicating that the transfer has been done
/// correctly or a VerificationError indicating what failed (the EncTrans
/// protocol or the bulletproof)
#[allow(clippy::too_many_arguments)]
pub fn verify_sec_to_pub_trans<C: Curve>(
    context: &GlobalContext<C>,
    ro: RandomOracle,
    transcript: &mut Transcript,
    transaction: &SecToPubAmountTransferData<C>,
    pk: &PublicKey<C>,
    S: &Cipher<C>,
) -> Result<(), VerificationError> {
    let generator = context.encryption_in_exponent_generator();
    let gens = context.bulletproof_generators();
    let a = transaction.transfer_amount;
    let A_dummy_encryption = {
        let ha = generator.mul_by_scalar(&C::scalar_from_u64(u64::from(a)));
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

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::G1;
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

        let context = GlobalContext::<SomeCurve>::generate_size(nm);
        let generator = context.encryption_in_exponent_generator(); // h
        let s_value = Value::from_u64(s);
        let S = pk.encrypt_exponent_given_generator(&mut csprng, &s_value, generator);

        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);

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
            Amount::from(s),
            Amount::from(a),
            &mut csprng,
        )
        .unwrap();
        let mut transcript = Transcript::new(&[]);

        assert_eq!(
            verify_sec_to_pub_trans(&context, ro, &mut transcript, &transaction, &pk, &S,),
            Ok(())
        )
    }
}
