//! This module implements the proof of knowledge of signature sigma protocol.
//! This protocol allows a user to prove knowledge of a signature without
//! revealing the original signature, or the message, but they have to reveal
//! the blinded version of the signature, and commitments to the values that
//! were signed.

use curve_arithmetic::curve_arithmetic::*;
use ff::Field;
use rand::*;

use crypto_common::*;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use ps_sig::{BlindedSignature, BlindingRandomness, PublicKey as PsSigPublicKey};
use random_oracle::RandomOracle;

#[derive(Clone, Debug, Eq, Serialize)]
pub struct ComEqSigProof<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The challenge computed by the prover.
    challenge: P::ScalarField,
    /// The witness that the prover knows $r'$ (see specification)
    witness_rho: P::ScalarField,
    /// List of witnesses $(w_i, R_i)$ that the user knows the messages m_i and
    /// randomness R_i that combine to commitments and the public randomized
    /// signature.
    #[size_length = 4]
    witness_commit: Vec<(P::ScalarField, C::Scalar)>,
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> PartialEq for ComEqSigProof<P, C> {
    fn eq(&self, other: &Self) -> bool {
        self.challenge == other.challenge
            && self.witness_rho == other.witness_rho
            && self.witness_commit == other.witness_commit
    }
}

pub struct ComEqSigSecret<'a, P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub blind_rand:       &'a BlindingRandomness<P>,
    pub values_and_rands: &'a [(Value<C>, &'a Randomness<C>)],
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
/// Construct a proof of knowledge of a signature.
/// The arguments are as follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `blinded_sig` - The blinded signature
/// * `commitments` - A list of commitments that were signed.
/// * `ps_pub_key` - The Pointcheval-Sanders public key with which the signature
///   was generated
/// * `comm_key` - A commitment key with which the commitments were generated.
/// * `secret` - The pair of 'BlindingRandomness', and the vector of pairs
///   $(m_i, r_i)$ of the commited to message $m_i$ and randomness $r_i$.
/// * `csprng` - A cryptographically secure random number generator.
///
/// This function assumes that
/// * the list of commitments has the same length as the list of pairs $(m_i,
///   r_i)$
/// * The Pointcheval-Sanders public key is at least as long (the $Y_i$
///   component) as the vector of commitments.
pub fn prove_com_eq_sig<P: Pairing, C: Curve<Scalar = P::ScalarField>, R: Rng>(
    ro: RandomOracle,
    blinded_sig: &BlindedSignature<P>,
    commitments: &[Commitment<C>],
    ps_pub_key: &PsSigPublicKey<P>,
    comm_key: &CommitmentKey<C>,
    secret: &ComEqSigSecret<P, C>,
    csprng: &mut R,
) -> ComEqSigProof<P, C> {
    let g_tilda = ps_pub_key.g_tilda;
    let a_hat = blinded_sig.sig.0;
    let _b_hat = blinded_sig.sig.1;
    let _cX_tilda = ps_pub_key.x_tilda;
    let cY_tilda = |i| ps_pub_key.y_tildas[i];
    let cmm_key = comm_key;

    let r_prime = secret.blind_rand.1;

    let n = secret.values_and_rands.len();
    // FIXME: Likely these assertions should be turned into return values
    // indicating what went wrong.
    assert_eq!(
        n,
        commitments.len(),
        "List of commitments must be the same length as the list of messages."
    );
    assert!(
        n <= (ps_pub_key).y_tildas.len(),
        "The PS key must be at least das long as the list of commitments."
    );

    let mut hasher = ro
        .append_bytes("com_eq_sig")
        .append(blinded_sig)
        .extend_from(commitments.iter())
        .append(ps_pub_key)
        .append(comm_key);

    // Random elements corresponding to the messages m_i, used as witnesses
    // for the aggregate log part of the proof, and the randomness R_i used
    // for the commitment part of the proof.
    let mut mus_cRs = Vec::with_capacity(n);

    // randomness corresponding to the r_prime (r').
    let rho_prime = <P::G2 as Curve>::generate_non_zero_scalar(csprng);

    // The auxiliary point which we are going to pair with a_hat to obtain the final
    // challenge. This is using the bilinearity property of pairings and differs
    // from the specification in the way the computation is carried out, but
    // not in the observable outcomes.
    let mut point = g_tilda.mul_by_scalar(&rho_prime);

    for i in 0..n {
        // Random value.
        let mu_i = Value::generate_non_zero(csprng);

        // And a point in G2 computed from it.
        let cU_i = cY_tilda(i).mul_by_scalar(&mu_i);
        // A commitment to the value v_i, and a randomness
        let (c_i, cR_i) = cmm_key.commit(&mu_i, csprng);

        // Save these for later
        mus_cRs.push((mu_i, cR_i));

        // And add the commitment c_i directly to the hash
        hasher.add(&c_i);
        // And the other point to the running total (since we have to hash the result of
        // the pairing)
        point = point.plus_point(&cU_i);
    }
    // // add X_tilda (corresponds to multiplying by v_3)
    // let v_2_pre_pair = cX_tilda.plus_point(&point);
    // let v_2_pair = P::pair(a_hat, v_2_pre_pair);
    let paired = P::pair(&a_hat, &point);
    // TODO: here we could assert and check that v_2_pair = pair(b_hat, g_tilda)
    // This should be the case if the input is valid.

    let challenge = hasher.finish_to_scalar::<C, _>(&paired);
    // If challange = 0 the proof is not going to be valid.
    // However this is an exceedingly unlikely case
    let mut wit_r_prime: P::ScalarField = challenge;
    wit_r_prime.mul_assign(&r_prime);
    wit_r_prime.negate();
    wit_r_prime.add_assign(&rho_prime);

    let mut wit_messages_randoms = Vec::with_capacity(n);
    for ((ref m, r), (ref mu, ref rho)) in izip!(secret.values_and_rands, mus_cRs) {
        let mut wit_m = challenge;
        wit_m.mul_assign(m);
        wit_m.negate();
        wit_m.add_assign(mu);

        let mut wit_r = challenge;
        wit_r.mul_assign(r);
        wit_r.negate();
        wit_r.add_assign(rho);

        wit_messages_randoms.push((wit_m, wit_r));
    }
    ComEqSigProof {
        challenge,
        witness_rho: wit_r_prime,
        witness_commit: wit_messages_randoms,
    }
}

#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
/// Verify a proof of knowledge of a signature.
/// The arguments are as follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `blinded_sig` - The blinded signature
/// * `commitments` - A list of commitments that were signed.
/// * `ps_pub_key` - The Pointcheval-Sanders public key with which the signature
///   was generated
/// * `comm_key` - A commitment key with which the commitments were generated.
/// * `proof` - A proof of knowledge of equality between commitments and
///   signature message
pub fn verify_com_eq_sig<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    ro: RandomOracle,
    blinded_sig: &BlindedSignature<P>,
    commitments: &[Commitment<C>],
    ps_pub_key: &PsSigPublicKey<P>,
    comm_key: &CommitmentKey<C>,
    proof: &ComEqSigProof<P, C>,
) -> bool {
    let g_tilda = ps_pub_key.g_tilda;
    let a_hat = blinded_sig.sig.0;
    let b_hat = blinded_sig.sig.1;
    let cX_tilda = ps_pub_key.x_tilda;
    let cY_tildas = &ps_pub_key.y_tildas;
    let cmm_key = comm_key;

    let mut hasher = ro
        .append_bytes("com_eq_sig")
        .append(blinded_sig)
        .extend_from(commitments.iter())
        .append(ps_pub_key)
        .append(comm_key);

    let commitments = &commitments;
    if commitments.len() != proof.witness_commit.len() {
        return false;
    }
    if commitments.len() > cY_tildas.len() {
        return false;
    }

    let mut point = g_tilda.mul_by_scalar(&proof.witness_rho);
    for (cC_i, cY_tilda, (wit_m, wit_r)) in
        izip!(commitments.iter(), cY_tildas, proof.witness_commit.iter())
    {
        // compute C_i^c * g^mu_i h^R_i
        let cP = cC_i
            .mul_by_scalar(&proof.challenge)
            .plus_point(&cmm_key.hide(Value::view_scalar(wit_m), Randomness::view_scalar(wit_r)));
        hasher.add(&cP);

        point = point.plus_point(&cY_tilda.mul_by_scalar(&wit_m));
    }
    // finally add X_tilda
    let point = point.plus_point(&cX_tilda.inverse_point().mul_by_scalar(&proof.challenge));

    // We have now computed a point `point` such that
    // ```v_3^{-c} * v_1^R \prod u_i^w_i = e(a_hat, point)```
    // If the proof is correct then the challenge was computed with
    // v_2^c * v^3{-c} * ...
    // where * is the multiplication in the target field (of which the G_T is a multiplicative subgroup).

    // Combine the pairing computations to compute the product.
    let paired = P::pairing_product(
        &b_hat,
        &g_tilda.mul_by_scalar(&proof.challenge),
        &a_hat,
        &point,
    );

    if let Some(paired) = paired {
        let computed_challenge = hasher.finish_to_scalar::<C, _>(&paired);
        computed_challenge == proof.challenge
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_protocols::common::*;
    use pairing::bls12_381::{Bls12, G1};
    use ps_sig::{SecretKey as PsSigSecretKey, SigRetrievalRandomness, UnknownMessage};

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_correctness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let ps_sk: PsSigSecretKey<Bls12> = PsSigSecretKey::generate(i, &mut csprng);
            let ps_pk: PsSigPublicKey<Bls12> = PsSigPublicKey::from(&ps_sk);
            let cmm_key = CommitmentKey::generate(&mut csprng);

            let mut secrets = Vec::with_capacity(i);
            // commitment to the signer.
            // the randomness used to mask the actual values.
            let mask = <Bls12 as Pairing>::generate_non_zero_scalar(&mut csprng);
            let mut comm_to_signer: G1 = ps_pk.g.mul_by_scalar(&mask);
            let mut commitments = Vec::with_capacity(i);
            for cY_j in ps_pk.ys.iter() {
                let v_j = Value::generate(&mut csprng);
                let (c_j, r_j) = cmm_key.commit(&v_j, &mut csprng);
                comm_to_signer = comm_to_signer.plus_point(&cY_j.mul_by_scalar(&v_j));
                secrets.push((v_j, Box::leak(Box::new(r_j)) as &_));
                commitments.push(c_j);
            }
            let unknown_message = UnknownMessage(comm_to_signer);
            let sig = ps_sk
                .sign_unknown_message(&unknown_message, &mut csprng)
                .retrieve(&SigRetrievalRandomness::<Bls12> { randomness: mask });
            let (blinded_sig, blind_rand) = sig.blind(&mut csprng);

            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);

            let secret = ComEqSigSecret {
                blind_rand:       &blind_rand,
                values_and_rands: &secrets,
            };
            let proof = prove_com_eq_sig::<Bls12, <Bls12 as Pairing>::G1, _>(
                ro.split(),
                &blinded_sig,
                &commitments,
                &ps_pk,
                &cmm_key,
                &secret,
                &mut csprng,
            );
            assert!(verify_com_eq_sig(
                ro.split(),
                &blinded_sig,
                &commitments,
                &ps_pk,
                &cmm_key,
                &proof
            ));
        }
    }

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_soundness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            // Generate proof
            let ps_sk: PsSigSecretKey<Bls12> = PsSigSecretKey::generate(i, &mut csprng);
            let ps_pk: PsSigPublicKey<Bls12> = PsSigPublicKey::from(&ps_sk);
            let cmm_key = CommitmentKey::generate(&mut csprng);

            let mut secrets = Vec::with_capacity(i);
            let mask = <Bls12 as Pairing>::generate_non_zero_scalar(&mut csprng);
            let mut comm_to_signer: G1 = ps_pk.g.mul_by_scalar(&mask);
            let mut commitments = Vec::with_capacity(i);
            for cY_j in ps_pk.ys.iter() {
                let v_j = Value::generate(&mut csprng);
                let (c_j, r_j) = cmm_key.commit(&v_j, &mut csprng);
                comm_to_signer = comm_to_signer.plus_point(&cY_j.mul_by_scalar(&v_j));
                secrets.push((v_j, Box::leak(Box::new(r_j)) as &_));
                commitments.push(c_j);
            }
            let unknown_message = UnknownMessage(comm_to_signer);
            let sig = ps_sk
                .sign_unknown_message(&unknown_message, &mut csprng)
                .retrieve(&SigRetrievalRandomness::<Bls12> { randomness: mask });
            let (blinded_sig, blind_rand) = sig.blind(&mut csprng);

            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);

            let secret = ComEqSigSecret {
                blind_rand:       &blind_rand,
                values_and_rands: &secrets,
            };
            let proof = prove_com_eq_sig::<Bls12, <Bls12 as Pairing>::G1, _>(
                ro.split(),
                &blinded_sig,
                &commitments,
                &ps_pk,
                &cmm_key,
                &secret,
                &mut csprng,
            );

            // Construct invalid parameters
            let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));

            let (wrong_blinded_sig, _) = sig.blind(&mut csprng);

            let (wrong_comm, _) = cmm_key.commit(&Value::generate(&mut csprng), &mut csprng);
            let mut wrong_commitments = commitments.to_owned();
            wrong_commitments[0] = wrong_comm;

            let wrong_ps_sk: PsSigSecretKey<Bls12> = PsSigSecretKey::generate(i, &mut csprng);
            let wrong_ps_pk: PsSigPublicKey<Bls12> = PsSigPublicKey::from(&wrong_ps_sk);

            let wrong_cmm_key = CommitmentKey::generate(&mut csprng);

            // Verify failure for invalid parameters
            assert!(!verify_com_eq_sig(
                wrong_ro,
                &blinded_sig,
                &commitments,
                &ps_pk,
                &cmm_key,
                &proof
            ));
            assert!(!verify_com_eq_sig(
                ro.split(),
                &wrong_blinded_sig,
                &commitments,
                &ps_pk,
                &cmm_key,
                &proof
            ));
            assert!(!verify_com_eq_sig(
                ro.split(),
                &blinded_sig,
                &wrong_commitments,
                &ps_pk,
                &cmm_key,
                &proof
            ));
            assert!(!verify_com_eq_sig(
                ro.split(),
                &blinded_sig,
                &commitments,
                &wrong_ps_pk,
                &cmm_key,
                &proof
            ));
            assert!(!verify_com_eq_sig(
                ro.split(),
                &blinded_sig,
                &commitments,
                &ps_pk,
                &wrong_cmm_key,
                &proof
            ));
        }
    }
}
