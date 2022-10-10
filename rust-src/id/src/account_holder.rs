//! Functionality needed by the account holder, either when interacting with the
//! identity provider, or when interacting with the chain.
use crate::{
    secret_sharing::*,
    sigma_protocols::{
        com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult, common::*, dlog,
    },
    types::*,
    utils,
};
use anyhow::{bail, ensure};
use bulletproofs::{
    inner_product_proof::inner_product,
    range_proof::{prove_given_scalars as bulletprove, prove_less_than_or_equal, RangeProof},
};
use crypto_common::types::TransactionTime;
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf as prf;
use elgamal::{multicombine, Cipher};
use ff::Field;
use pedersen_scheme::{
    Commitment, CommitmentKey as PedersenKey, Randomness as PedersenRandomness, Value,
};
use rand::*;
use random_oracle::RandomOracle;
use std::collections::{btree_map::BTreeMap, hash_map::HashMap, BTreeSet};

/// Build the PublicInformationForIP used to generate an PreIdentityObject, out
/// of the account holder information and the necessary contextual
/// information (group generators, shared commitment keys, etc).
/// NB: this function cannot be inlined in generate_pio, as it is used
/// externally.
pub fn build_pub_info_for_ip<C: Curve>(
    gc: &GlobalContext<C>,
    id_cred_sec: &Value<C>,
    prf_key: &prf::SecretKey<C>,
    initial_account: &impl PublicInitialAccountData,
) -> Option<PublicInformationForIp<C>> {
    let id_cred_pub = gc.on_chain_commitment_key.g.mul_by_scalar(id_cred_sec);

    // From create_credential:
    // let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
    let reg_id_exponent = match prf_key.prf_exponent(crate::constants::INITIAL_CREDENTIAL_INDEX) {
        Ok(exp) => exp,
        Err(_) => return None,
    };

    // RegId as well as Prf key commitments must be computed
    // with the same generators as in the commitment key.
    let reg_id = gc
        .on_chain_commitment_key
        .hide(
            &Value::<C>::new(reg_id_exponent),
            &PedersenRandomness::zero(),
        )
        .0;

    let vk_acc = initial_account.get_cred_key_info();

    let pub_info_for_ip = PublicInformationForIp {
        id_cred_pub,
        reg_id,
        vk_acc,
        // policy
    };
    Some(pub_info_for_ip)
}

/// Two flows for creating identities are supported. The first flow involves the
/// creation of an initial account, the second flow does not.
/// The proofs used in the flows are very similar, and therefore factored out in
/// the function `generate_pio_common` that constructs the common sigma protocol
/// prover used in both flows:
/// * In the version 0 flow, the common prover is AND'ed with a prover showing
///   that RegID = PRF(key_PRF, 0)
/// * In the version 1 flow, the sigma protocol prover is the common prover
/// The `generate_pio_common` function also produces the bulletproofs rangeproof
/// used in both flows. The version 0 flow is kept for backwards compatibility.

/// Generate a version 0 PreIdentityObject out of the account holder
/// information, the chosen anonymity revoker information, and the necessary
/// contextual information (group generators, shared commitment keys, etc).
/// NB: In this method we assume that all the anonymity revokers in context
/// are to be used.
pub fn generate_pio<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    context: &IpContext<P, C>,
    threshold: Threshold,
    id_use_data: &IdObjectUseData<P, C>,
    initial_account: &impl InitialAccountDataWithSigning,
) -> Option<(PreIdentityObject<P, C>, ps_sig::SigRetrievalRandomness<P>)> {
    let mut csprng = thread_rng();
    let mut transcript = RandomOracle::domain("PreIdentityProof");
    // Prove ownership of the initial account
    let pub_info_for_ip = build_pub_info_for_ip(
        context.global_context,
        &id_use_data.aci.cred_holder_info.id_cred.id_cred_sec,
        &id_use_data.aci.prf_key,
        initial_account,
    )?;
    let proof_acc_sk = AccountOwnershipProof {
        sigs: initial_account.sign_public_information_for_ip(&pub_info_for_ip),
    };
    let CommonPioGenerationOutput{
        prover,
        secret,
        bulletproofs,
        ip_ar_data,
        choice_ar_parameters,
        cmm_prf_sharing_coeff,
        .. // id_cred_pub already in pub_info_for_ip
     } = generate_pio_common(
        &mut transcript,
        &mut csprng,
        context,
        threshold,
        id_use_data,
    )?;
    // Additionally prove that RegID = PRF(key_PRF, 0):
    let prover_prf_regid = com_eq::ComEq {
        commitment: prover.first.second.commitment_1,
        y:          context.global_context.on_chain_commitment_key.g,
        g:          pub_info_for_ip.reg_id,
        cmm_key:    prover.first.second.cmm_key_1,
    };

    let secret_prf_regid = com_eq::ComEqSecret {
        r: secret.0 .1.rand_cmm_1.clone(),
        a: id_use_data.aci.prf_key.to_value(),
    };
    // Add the prf_regid prover and secret
    let prover = prover.add_prover(prover_prf_regid);
    let secret = (secret, secret_prf_regid);
    transcript.append_message(b"bulletproofs", &bulletproofs);
    // Randomness to retrieve the signature
    // We add randomness from both of the commitments.
    // See specification of ps_sig and id layer for why this is so.
    let mut sig_retrieval_rand = P::ScalarField::zero();
    sig_retrieval_rand.add_assign(&secret.0 .0 .0 .1.r);
    sig_retrieval_rand.add_assign(&secret.0 .0 .1.rand_cmm_1);
    let proof = prove(&mut transcript, &prover, secret, &mut csprng)?;

    let ip_ar_data = ip_ar_data
        .iter()
        .zip(proof.witness.w1.w2.witnesses.into_iter())
        .map(|((ar_id, f), w)| (*ar_id, f(w)))
        .collect::<BTreeMap<ArIdentity, _>>();

    // Returning the version 0 pre-identity object.
    let poks_common = CommonPioProofFields {
        challenge: proof.challenge,
        id_cred_sec_witness: proof.witness.w1.w1.w1.w1,
        commitments_same_proof: proof.witness.w1.w1.w1.w2,
        commitments_prf_same: proof.witness.w1.w1.w2,
        bulletproofs,
    };
    let poks = PreIdentityProof {
        common_proof_fields: poks_common,
        prf_regid_proof: proof.witness.w2,
        proof_acc_sk,
    };
    let pio = PreIdentityObject {
        pub_info_for_ip,
        ip_ar_data,
        choice_ar_parameters,
        cmm_sc: prover.first.first.first.second.commitment,
        cmm_prf: prover.first.first.second.commitment_1,
        cmm_prf_sharing_coeff,
        poks,
    };
    Some((pio, ps_sig::SigRetrievalRandomness::new(sig_retrieval_rand)))
}

/// Generate a version 1 PreIdentityObject out of the account holder
/// information, the chosen anonymity revoker information, and the necessary
/// contextual information (group generators, shared commitment keys, etc).
/// NB: In this method we assume that all the anonymity revokers in context
/// are to be used.
pub fn generate_pio_v1<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    // TODO: consider renaming this function
    context: &IpContext<P, C>,
    threshold: Threshold,
    id_use_data: &IdObjectUseData<P, C>,
) -> Option<(PreIdentityObjectV1<P, C>, ps_sig::SigRetrievalRandomness<P>)> {
    let mut csprng = thread_rng();
    let mut transcript = RandomOracle::domain("PreIdentityProof");
    let CommonPioGenerationOutput {
        prover,
        secret,
        bulletproofs,
        ip_ar_data,
        choice_ar_parameters,
        cmm_prf_sharing_coeff,
        id_cred_pub,
    } = generate_pio_common(
        &mut transcript,
        &mut csprng,
        context,
        threshold,
        id_use_data,
    )?;
    transcript.append_message(b"bulletproofs", &bulletproofs);
    // Randomness to retrieve the signature
    // We add randomness from both of the commitments.
    // See specification of ps_sig and id layer for why this is so.
    let mut sig_retrieval_rand = P::ScalarField::zero();
    sig_retrieval_rand.add_assign(&secret.0 .0 .1.r);
    sig_retrieval_rand.add_assign(&secret.0 .1.rand_cmm_1);
    let proof = prove(&mut transcript, &prover, secret, &mut csprng)?;

    let ip_ar_data = ip_ar_data
        .iter()
        .zip(proof.witness.w2.witnesses.into_iter())
        .map(|((ar_id, f), w)| (*ar_id, f(w)))
        .collect::<BTreeMap<ArIdentity, _>>();

    // Returning the version 1 pre-identity object.
    let poks = CommonPioProofFields {
        challenge: proof.challenge,
        id_cred_sec_witness: proof.witness.w1.w1.w1,
        commitments_same_proof: proof.witness.w1.w1.w2,
        commitments_prf_same: proof.witness.w1.w2,
        bulletproofs,
    };
    let pio = PreIdentityObjectV1 {
        id_cred_pub,
        ip_ar_data,
        choice_ar_parameters,
        cmm_sc: prover.first.first.second.commitment,
        cmm_prf: prover.first.second.commitment_1,
        cmm_prf_sharing_coeff,
        poks,
    };
    Some((pio, ps_sig::SigRetrievalRandomness::new(sig_retrieval_rand)))
}

/// Type alias for the sigma protocol prover that are used by both
/// `generate_pio` and `generate_pio_v1`.
type CommonPioProverType<P, C> = AndAdapter<
    AndAdapter<
        AndAdapter<dlog::Dlog<C>, com_eq::ComEq<C, <P as Pairing>::G1>>,
        com_eq_different_groups::ComEqDiffGroups<<P as Pairing>::G1, C>,
    >,
    ReplicateAdapter<com_enc_eq::ComEncEq<C>>,
>;

type IpArDataClosures<'a, C> = Vec<(
    ArIdentity,
    Box<dyn Fn(com_enc_eq::Witness<C>) -> IpArData<C> + 'a>,
)>;

/// Various data returned by `generate_pio_common` needed by both
/// `generate_pio` and `generate_pio_v1` in order to produce the relevant
/// pre-identity object.
struct CommonPioGenerationOutput<'a, P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    prover:                CommonPioProverType<P, C>,
    secret:                <CommonPioProverType<P, C> as SigmaProtocol>::SecretData,
    bulletproofs:          Vec<RangeProof<C>>,
    ip_ar_data:            IpArDataClosures<'a, C>,
    choice_ar_parameters:  ChoiceArParameters,
    cmm_prf_sharing_coeff: Vec<Commitment<C>>,
    id_cred_pub:           C,
}

/// Function for generating the common parts of a pre-identity object. This
/// includes constructing the sigma protocol prover that are used by both
/// `generate_pio` and `generate_pio_v1` to generate a version 0 and version 1
/// pre-identity object, respectively.
fn generate_pio_common<'a, P: Pairing, C: Curve<Scalar = P::ScalarField>, R: rand::Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    context: &IpContext<'a, P, C>,
    threshold: Threshold,
    id_use_data: &IdObjectUseData<P, C>,
) -> Option<CommonPioGenerationOutput<'a, P, C>> {
    let aci = &id_use_data.aci;

    // PRF related computation
    let prf_key = &aci.prf_key;

    let prf_value = aci.prf_key.to_value();

    let ar_commitment_key = &context.global_context.on_chain_commitment_key;

    let (prf_key_data, cmm_prf_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data_prf(
        &prf_value,
        context.ars_infos,
        threshold,
        context.global_context,
    );
    let number_of_ars = context.ars_infos.len();
    let mut ip_ar_data = Vec::with_capacity(number_of_ars);

    // Commit and prove knowledge of id_cred_sec
    let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
    let sc_ck = PedersenKey {
        g: context.ip_info.ip_verify_key.ys[0],
        h: context.ip_info.ip_verify_key.g,
    };

    let (cmm_sc, cmm_sc_rand) = sc_ck.commit(&id_cred_sec, csprng);
    // We now construct all the zero-knowledge proofs.
    // Since all proofs must be bound together, we
    // first construct inputs to all the proofs, and only at the end
    // do we produce all the different witnesses.

    // First the proof that we know id_cred_sec.
    let id_cred_pub = context
        .global_context
        .on_chain_commitment_key
        .g
        .mul_by_scalar(id_cred_sec);
    let prover = dlog::Dlog::<C> {
        public: id_cred_pub,
        coeff:  context.global_context.on_chain_commitment_key.g,
    };
    let secret = dlog::DlogSecret {
        secret: id_cred_sec.clone(),
    };

    // Next the proof that id_cred_sec is the same both in id_cred_pub
    // and in the commitment to id_cred_sec (cmm_sc).
    let prover = AndAdapter {
        first:  prover,
        second: com_eq::ComEq {
            commitment: cmm_sc,
            y:          id_cred_pub,
            cmm_key:    sc_ck,
            g:          context.global_context.on_chain_commitment_key.g,
        },
    };
    let secret = (secret, com_eq::ComEqSecret::<P::G1> {
        r: cmm_sc_rand.clone(),
        a: id_cred_sec.view(),
    });

    // Commit to the PRF key for the IP and prove equality for the secret-shared PRF
    // key
    let commitment_key_prf = PedersenKey {
        g: context.ip_info.ip_verify_key.ys[1],
        h: context.ip_info.ip_verify_key.g,
    };
    // let (cmm_prf, rand_cmm_prf) = commitment_key_prf.commit(prf_key, &mut
    // csprng);
    let mut rand_cmm_prf_scalar = *id_use_data.randomness; // m_0 from the bluepaper
    rand_cmm_prf_scalar.sub_assign(&cmm_sc_rand);
    let rand_cmm_prf = PedersenRandomness::new(rand_cmm_prf_scalar);
    let cmm_prf = commitment_key_prf.hide(prf_key, &rand_cmm_prf);
    let snd_cmm_prf = cmm_prf_sharing_coeff.first()?;
    let rand_snd_cmm_prf = cmm_coeff_randomness.first()?.clone();

    // Next the proof that the two commitments to the prf key are the same.
    let prover = prover.add_prover(com_eq_different_groups::ComEqDiffGroups {
        commitment_1: cmm_prf,
        commitment_2: *snd_cmm_prf,
        cmm_key_1:    commitment_key_prf,
        cmm_key_2:    *ar_commitment_key,
    });
    let secret = (secret, com_eq_different_groups::ComEqDiffGroupsSecret {
        value:      prf_key.to_value(),
        rand_cmm_1: rand_cmm_prf,
        rand_cmm_2: rand_snd_cmm_prf,
    });

    // Now we produce a list of proofs relating to the encryption to the anonymity
    // revoker of all the shares.
    // Fill IpArData with data for each anonymity revoker
    //   - The AR id
    //   - An encryption under AR publickey of his share of the PRF key
    //   - The ARs share number (x-coordinate of polynomial)
    //   - ZK-proof that the encryption has same value as corresponding commitment

    let mut replicated_provers = Vec::with_capacity(prf_key_data.len());
    let mut replicated_secrets = Vec::with_capacity(prf_key_data.len());
    let mut bulletproofs = Vec::with_capacity(prf_key_data.len());
    // Extract identities of the chosen ARs for use in PIO
    let ar_identities = context.ars_infos.keys().copied().collect();
    let choice_ar_parameters = ChoiceArParameters {
        ar_identities,
        threshold,
    };

    transcript.append_message(b"ctx", &context.global_context);
    transcript.append_message(b"choice_ar_parameters", &choice_ar_parameters);
    transcript.append_message(b"cmm_sc", &cmm_sc);
    transcript.append_message(b"cmm_prf", &cmm_prf);
    transcript.append_message(b"cmm_prf_sharing_coeff", &cmm_prf_sharing_coeff);

    for item in prf_key_data {
        let u8_chunk_size = u8::from(CHUNK_SIZE);
        let two_chunksize = C::scalar_from_u64(1 << u8_chunk_size);
        let mut power_of_two = C::Scalar::one();
        let mut scalars = Vec::with_capacity(item.encrypted_share.len());
        for _ in 0..item.encrypted_share.len() {
            scalars.push(power_of_two);
            power_of_two.mul_assign(&two_chunksize);
        }
        let combined_ciphers = multicombine(&item.encrypted_share, &scalars);
        let rands_as_scalars: Vec<C::Scalar> = item
            .encryption_randomness
            .iter()
            .map(|x| **x)
            .collect::<Vec<_>>();
        let combined_rands = inner_product::<C::Scalar>(&rands_as_scalars, &scalars);
        let combined_encryption_randomness = elgamal::Randomness::new(combined_rands);
        let secret = com_enc_eq::ComEncEqSecret {
            value:         item.share.clone(),
            elgamal_rand:  combined_encryption_randomness,
            pedersen_rand: item.randomness_cmm_to_share.clone(),
        };
        // FIXME: Need some context in the challenge computation.
        let h_in_exponent = *context.global_context.encryption_in_exponent_generator();
        let item_prover = com_enc_eq::ComEncEq {
            cipher: combined_ciphers,
            commitment: item.cmm_to_share,
            pub_key: item.ar.ar_public_key,
            cmm_key: *ar_commitment_key,
            encryption_in_exponent_generator: h_in_exponent,
        };
        replicated_provers.push(item_prover);
        replicated_secrets.push(secret);
        let encrypted_share = item.encrypted_share;
        let closure: Box<dyn Fn(com_enc_eq::Witness<C>) -> IpArData<C> + 'a> =
            Box::new(move |proof_com_enc_eq| IpArData {
                enc_prf_key_share: encrypted_share,
                proof_com_enc_eq,
            });
        ip_ar_data.push((item.ar.ar_identity, closure));
        transcript.append_message(b"encrypted_share", &item.encrypted_share);
        let cmm_key_bulletproof = PedersenKey {
            g: h_in_exponent,
            h: item.ar.ar_public_key.key,
        };
        let rand_bulletproof = item
            .encryption_randomness
            .iter()
            .map(|x| PedersenRandomness::new(*x.as_ref()))
            .collect::<Vec<_>>();
        let bulletproof = bulletprove(
            transcript,
            csprng,
            u8::from(CHUNK_SIZE),
            item.share_in_chunks.len() as u8,
            &item.share_in_chunks,
            &context.global_context.bulletproof_generators().take(32 * 8),
            &cmm_key_bulletproof,
            &rand_bulletproof,
        )?;
        bulletproofs.push(bulletproof);
    }

    let prover = prover.add_prover(ReplicateAdapter {
        protocols: replicated_provers,
    });
    let secret = (secret, replicated_secrets);

    Some(CommonPioGenerationOutput {
        prover,
        secret,
        bulletproofs,
        ip_ar_data,
        choice_ar_parameters,
        cmm_prf_sharing_coeff,
        id_cred_pub,
    })
}

/// Convenient data structure to collect data related to a single AR
pub struct SingleArData<'a, C: Curve> {
    pub ar:                  &'a ArInfo<C>,
    share:                   Value<C>,
    pub encrypted_share:     Cipher<C>,
    encryption_randomness:   elgamal::Randomness<C>,
    pub cmm_to_share:        Commitment<C>,
    randomness_cmm_to_share: PedersenRandomness<C>,
}

type SharingData<'a, C> = (
    Vec<SingleArData<'a, C>>,
    Vec<Commitment<C>>, /* Commitments to the coefficients of sharing polynomial S + b1 X + b2
                         * X^2... */
    Vec<PedersenRandomness<C>>,
);

/// A function to compute sharing data for a single value.
pub fn compute_sharing_data<'a, C: Curve>(
    shared_scalar: &Value<C>,                           // Value to be shared.
    ar_parameters: &'a BTreeMap<ArIdentity, ArInfo<C>>, // Chosen anonimity revokers.
    threshold: Threshold,                               // Anonymity revocation threshold.
    commitment_key: &PedersenKey<C>,                    // commitment key
) -> SharingData<'a, C> {
    let n = ar_parameters.len() as u32;
    let mut csprng = thread_rng();
    // first commit to the scalar
    let (cmm_scalar, cmm_scalar_rand) = commitment_key.commit(&shared_scalar, &mut csprng);
    // We evaluate the polynomial at ar_identities.
    let share_points = ar_parameters.keys().copied();
    // share the scalar on ar_identity points.
    let sharing_data = share::<C, _, _, _>(shared_scalar, share_points, threshold, &mut csprng);
    // commitments to the sharing coefficients
    let mut cmm_sharing_coefficients: Vec<Commitment<C>> = Vec::with_capacity(threshold.into());
    // first coefficient is the shared scalar
    cmm_sharing_coefficients.push(cmm_scalar);
    // randomness values corresponding to the commitments
    let mut cmm_coeff_randomness = Vec::with_capacity(threshold.into());
    // first randomness is the one used in commiting to the scalar
    cmm_coeff_randomness.push(cmm_scalar_rand);
    // fill the rest
    for coeff in sharing_data.coefficients.iter() {
        let (cmm, rnd) = commitment_key.commit(coeff, &mut csprng);
        cmm_sharing_coefficients.push(cmm);
        cmm_coeff_randomness.push(rnd);
    }
    // a vector of Ar data
    let mut ar_data: Vec<SingleArData<C>> = Vec::with_capacity(n as usize);
    // The correctness of this relies on the invariant that the map of anonymity
    // revokers has an anonymity revoker with ArIdentity = x at key x.
    for (ar, share) in izip!(ar_parameters.values(), sharing_data.shares.into_iter()) {
        let si = ar.ar_identity;
        let pk = ar.ar_public_key;
        // encrypt the share
        let (cipher, rnd2) = pk.encrypt_exponent_rand(&mut csprng, &share);
        // compute the commitment to this share from the commitment to the coeff
        let (cmm, rnd) =
            commitment_to_share_and_rand(si, &cmm_sharing_coefficients, &cmm_coeff_randomness);
        // fill Ar data
        let single_ar_data = SingleArData {
            ar,
            share,
            encrypted_share: cipher,
            encryption_randomness: rnd2,
            cmm_to_share: cmm,
            randomness_cmm_to_share: rnd,
        };
        ar_data.push(single_ar_data)
    }
    (ar_data, cmm_sharing_coefficients, cmm_coeff_randomness)
}

/// Convenient data structure to collect data related to a single AR
/// when encrypting the prf key in chunks
pub struct SingleArDataPrf<'a, C: Curve> {
    /// The relevant AR
    ar: &'a ArInfo<C>,
    /// The AR's share of the PRF key
    share: Value<C>,
    /// The share split in 8 chunks (written in little-endian)
    share_in_chunks: [C::Scalar; 8],
    /// Encryption of the share in chunks
    encrypted_share: [Cipher<C>; 8],
    /// Encryption randomness used to encrypt the share
    encryption_randomness: [elgamal::Randomness<C>; 8],
    /// Commitment to the share
    cmm_to_share: Commitment<C>,
    /// Randomness used in commitment to share
    randomness_cmm_to_share: PedersenRandomness<C>,
}

type SharingDataPrf<'a, C> = (
    Vec<SingleArDataPrf<'a, C>>,
    Vec<Commitment<C>>, /* Commitments to the coefficients of sharing polynomial S + b1 X + b2
                         * X^2... */
    Vec<PedersenRandomness<C>>,
);

/// A function to compute sharing data for a single value.
pub fn compute_sharing_data_prf<'a, C: Curve>(
    shared_scalar: &Value<C>,                           // Value to be shared.
    ar_parameters: &'a BTreeMap<ArIdentity, ArInfo<C>>, // Chosen anonimity revokers.
    threshold: Threshold,                               // Anonymity revocation threshold.
    global_context: &GlobalContext<C>,                  // commitment key
) -> SharingDataPrf<'a, C> {
    let commitment_key = &global_context.on_chain_commitment_key;
    let n = ar_parameters.len() as u32;
    let mut csprng = thread_rng();
    // first commit to the scalar
    let (cmm_scalar, cmm_scalar_rand) = commitment_key.commit(&shared_scalar, &mut csprng);
    // We evaluate the polynomial at ar_identities.
    let share_points = ar_parameters.keys().copied();
    // share the scalar on ar_identity points.
    let sharing_data = share::<C, _, _, _>(shared_scalar, share_points, threshold, &mut csprng);
    // commitments to the sharing coefficients
    let mut cmm_sharing_coefficients: Vec<Commitment<C>> = Vec::with_capacity(threshold.into());
    // first coefficient is the shared scalar
    cmm_sharing_coefficients.push(cmm_scalar);
    // randomness values corresponding to the commitments
    let mut cmm_coeff_randomness = Vec::with_capacity(threshold.into());
    // first randomness is the one used in commiting to the scalar
    cmm_coeff_randomness.push(cmm_scalar_rand);
    // fill the rest
    for coeff in sharing_data.coefficients.iter() {
        let (cmm, rnd) = commitment_key.commit(coeff, &mut csprng);
        cmm_sharing_coefficients.push(cmm);
        cmm_coeff_randomness.push(rnd);
    }
    // a vector of Ar data
    let mut ar_data: Vec<SingleArDataPrf<C>> = Vec::with_capacity(n as usize);
    // The correctness of this relies on the invariant that the map of anonymity
    // revokers has an anonymity revoker with ArIdentity = x at key x.
    for (ar, share) in izip!(ar_parameters.values(), sharing_data.shares.into_iter()) {
        let si = ar.ar_identity;
        let pk = ar.ar_public_key;
        // encrypt the share
        // let (cipher, rnd2) = pk.encrypt_exponent_rand(&mut csprng, &share);
        let (ciphers, rnd2, share_in_chunks) =
            utils::encrypt_prf_share(global_context, &pk, &share, &mut csprng);
        // compute the commitment to this share from the commitment to the coeff
        let (cmm, rnd) =
            commitment_to_share_and_rand(si, &cmm_sharing_coefficients, &cmm_coeff_randomness);
        // fill Ar data
        let single_ar_data = SingleArDataPrf {
            ar,
            share,
            share_in_chunks,
            encrypted_share: ciphers,
            encryption_randomness: rnd2,
            cmm_to_share: cmm,
            randomness_cmm_to_share: rnd,
        };
        ar_data.push(single_ar_data)
    }
    (ar_data, cmm_sharing_coefficients, cmm_coeff_randomness)
}

/// Computing the commitment to single share from the commitments to
/// the coefficients of the polynomial.
pub fn commitment_to_share_and_rand<C: Curve>(
    share_number: ArIdentity,
    coeff_commitments: &[Commitment<C>],
    coeff_randomness: &[PedersenRandomness<C>],
) -> (Commitment<C>, PedersenRandomness<C>) {
    assert_eq!(coeff_commitments.len(), coeff_randomness.len());

    let cmm = utils::commitment_to_share(&share_number.to_scalar::<C>(), coeff_commitments);

    let cmm_share_randomness_scalar =
        utils::evaluate_poly(coeff_randomness, &share_number.to_scalar::<C>());
    let rnd = PedersenRandomness::new(cmm_share_randomness_scalar);
    (cmm, rnd)
}

/// Generates a credential deployment info and outputs the randomness used in
/// commitments. The randomness should be stored for later use, e.g. to open
/// commitments later on. The information is meant to be valid in the context of
/// a given identity provider, and global parameter.
/// The 'cred_counter' is used to generate a new credential ID.
#[allow(clippy::too_many_arguments)]
pub fn create_credential<
    'a,
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    context: IpContext<'a, P, C>,
    id_object: &impl HasIdentityObjectFields<P, C, AttributeType>,
    id_object_use_data: &IdObjectUseData<P, C>,
    cred_counter: u8,
    policy: Policy<C, AttributeType>,
    cred_data: &impl CredentialDataWithSigning,
    secret_data: &impl HasAttributeRandomness<C>,
    new_or_existing: &either::Either<TransactionTime, AccountAddress>,
) -> anyhow::Result<(
    CredentialDeploymentInfo<P, C, AttributeType>,
    CommitmentsRandomness<C>,
)>
where
    AttributeType: Clone, {
    let (unsigned_credential_info, commitments_randomness) = create_unsigned_credential(
        context,
        id_object,
        id_object_use_data,
        cred_counter,
        policy,
        cred_data.get_cred_key_info(),
        new_or_existing.as_ref().right(),
        secret_data,
    )?;

    let proof_acc_sk = AccountOwnershipProof {
        sigs: cred_data.sign(new_or_existing, &unsigned_credential_info),
    };

    let cdp = CredDeploymentProofs {
        id_proofs: unsigned_credential_info.proofs,
        proof_acc_sk,
    };

    let info = CredentialDeploymentInfo {
        values: unsigned_credential_info.values,
        proofs: cdp,
    };

    Ok((info, commitments_randomness))
}

#[allow(clippy::too_many_arguments)]
pub fn create_unsigned_credential<
    'a,
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    context: IpContext<'a, P, C>,
    id_object: &impl HasIdentityObjectFields<P, C, AttributeType>,
    id_object_use_data: &IdObjectUseData<P, C>,
    cred_counter: u8,
    policy: Policy<C, AttributeType>,
    cred_key_info: CredentialPublicKeys,
    addr: Option<&AccountAddress>,
    secret_data: &impl HasAttributeRandomness<C>,
) -> anyhow::Result<(
    UnsignedCredentialDeploymentInfo<P, C, AttributeType>,
    CommitmentsRandomness<C>,
)>
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();

    let (ip_sig, prio, alist) = (
        id_object.get_signature(),
        id_object.get_common_pio_fields(),
        id_object.get_attribute_list(),
    );
    let sig_retrieval_rand = &id_object_use_data.randomness;
    let aci = &id_object_use_data.aci;

    let prf_key = &aci.prf_key;
    let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
    let cred_id_exponent = match aci.prf_key.prf_exponent(cred_counter) {
        Ok(exp) => exp,
        Err(_) => bail!(
            "Cannot create CDI with this account number because K + {} = 0.",
            cred_counter
        ),
    };

    // RegId as well as Prf key commitments must be computed
    // with the same generators as in the commitment key.
    let cred_id = context
        .global_context
        .on_chain_commitment_key
        .hide(
            &Value::<C>::new(cred_id_exponent),
            &PedersenRandomness::zero(),
        )
        .0;

    // Check that all the chosen identity providers (in the pre-identity object) are
    // available in the given context, and remove the ones that are not.
    let chosen_ars = {
        let mut chosen_ars = BTreeMap::new();
        for ar_id in prio.choice_ar_parameters.ar_identities.iter() {
            if let Some(info) = context.ars_infos.get(ar_id) {
                // FIXME: We could get rid of this clone if we passed in a map of references.
                let _ = chosen_ars.insert(*ar_id, info.clone()); // since we are
                                                                 // iterating over
                                                                 // a set, this
                                                                 // will always
                                                                 // be Some
            } else {
                bail!("Cannot find anonymity revoker {} in the context.", ar_id)
            }
        }
        chosen_ars
    };

    // sharing data for id cred sec
    let (id_cred_data, cmm_id_cred_sec_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data(
        id_cred_sec,
        &chosen_ars,
        prio.choice_ar_parameters.threshold,
        &context.global_context.on_chain_commitment_key,
    );

    let number_of_ars = prio.choice_ar_parameters.ar_identities.len();
    // filling ar data
    let ar_data = id_cred_data
        .iter()
        .map(|item| {
            (item.ar.ar_identity, ChainArData {
                enc_id_cred_pub_share: item.encrypted_share,
            })
        })
        .collect::<BTreeMap<_, _>>();

    let ip_pub_key = &context.ip_info.ip_verify_key;

    // retrieve the signature on the underlying idcredsec + prf_key + attribute_list
    let retrieved_sig = ip_sig.retrieve(sig_retrieval_rand);

    // and then we blind the signature to disassociate it from the message.
    // only the second part is used (as per the protocol)
    let (blinded_sig, blind_rand) = retrieved_sig.blind(&mut csprng);
    // We now compute commitments to all the items in the attribute list.
    // We use the on-chain pedersen commitment key.
    let (commitments, commitment_rands) = compute_commitments(
        &context.global_context.on_chain_commitment_key,
        alist,
        prf_key,
        cred_counter,
        &cmm_id_cred_sec_sharing_coeff,
        cmm_coeff_randomness,
        &policy,
        secret_data,
        &mut csprng,
    )?;

    // We have all the values now.
    let cred_values = CredentialDeploymentValues {
        cred_id,
        threshold: prio.choice_ar_parameters.threshold,
        ar_data,
        ip_identity: context.ip_info.ip_identity,
        policy,
        cred_key_info,
    };

    // We now produce all the proofs.
    // Compute the challenge prefix by hashing the values.
    // FIXME: We should do something different here.
    // Eventually we'll have to include the genesis hash.
    let mut ro = RandomOracle::domain("credential");
    ro.append_message(b"cred_values", &cred_values);
    ro.append_message(b"address", &addr);
    ro.append_message(b"global_context", &context.global_context);

    let mut id_cred_pub_share_numbers = Vec::with_capacity(number_of_ars);
    let mut id_cred_pub_provers = Vec::with_capacity(number_of_ars);
    let mut id_cred_pub_secrets = Vec::with_capacity(number_of_ars);

    // create provers for knowledge of id_cred_sec.
    for item in id_cred_data.iter() {
        let secret = com_enc_eq::ComEncEqSecret {
            value:         item.share.clone(),
            elgamal_rand:  item.encryption_randomness.clone(),
            pedersen_rand: item.randomness_cmm_to_share.clone(),
        };

        let item_prover = com_enc_eq::ComEncEq {
            cipher: item.encrypted_share,
            commitment: item.cmm_to_share,
            pub_key: item.ar.ar_public_key,
            cmm_key: context.global_context.on_chain_commitment_key,
            encryption_in_exponent_generator: item.ar.ar_public_key.generator,
        };

        id_cred_pub_share_numbers.push(item.ar.ar_identity);
        id_cred_pub_provers.push(item_prover);
        id_cred_pub_secrets.push(secret);
    }

    // Proof that the registration id is computed correctly from the prf key K and
    // the cred_counter x.
    let (prover_reg_id, secret_reg_id) = compute_pok_reg_id(
        &context.global_context.on_chain_commitment_key,
        prf_key.clone(),
        &commitments.cmm_prf,
        &commitment_rands.prf_rand,
        cred_counter,
        &commitments.cmm_cred_counter,
        &commitment_rands.cred_counter_rand,
        &commitment_rands.max_accounts_rand,
        cred_id_exponent,
        cred_id,
    );

    let choice_ar_handles = cred_values
        .ar_data
        .iter()
        .map(|(x, _)| *x)
        .collect::<BTreeSet<_>>();

    // Proof of knowledge of the signature of the identity provider.
    let (prover_sig, secret_sig) = compute_pok_sig(
        &context.global_context.on_chain_commitment_key,
        &commitments,
        &commitment_rands,
        id_cred_sec,
        prf_key,
        alist,
        prio.choice_ar_parameters.threshold,
        &choice_ar_handles,
        ip_pub_key,
        &blinded_sig,
        blind_rand,
    )?;

    let prover = AndAdapter {
        first:  prover_reg_id,
        second: prover_sig,
    };
    let prover = prover.add_prover(ReplicateAdapter {
        protocols: id_cred_pub_provers,
    });

    let secret = ((secret_reg_id, secret_sig), id_cred_pub_secrets);
    let proof = match prove(&mut ro, &prover, secret, &mut csprng) {
        Some(x) => x,
        None => bail!("Cannot produce zero knowledge proof."),
    };

    let cred_counter_less_than_max_accounts = match prove_less_than_or_equal(
        &mut ro,
        &mut csprng,
        8,
        u64::from(cred_counter),
        u64::from(alist.max_accounts),
        context.global_context.bulletproof_generators(),
        &context.global_context.on_chain_commitment_key,
        &commitment_rands.cred_counter_rand,
        &commitment_rands.max_accounts_rand,
    ) {
        Some(x) => x,
        None => bail!("Cannot produce proof that cred_counter <= max_accounts."),
    };

    // A list of signatures on the challenge used by the other proofs using the
    // credential keys.
    // The challenge has domain separator "credential" followed by appending all
    // values of the credential to the ro, specifically appending the
    // CredentialDeploymentValues struct.
    //
    // The domain seperator in combination with appending all the data of the
    // credential deployment should make it non-reusable.

    let id_proofs = IdOwnershipProofs {
        sig: blinded_sig,
        commitments,
        challenge: proof.challenge,
        proof_id_cred_pub: id_cred_pub_share_numbers
            .into_iter()
            .zip(proof.witness.w2.witnesses)
            .collect(),
        proof_reg_id: proof.witness.w1.w1,
        proof_ip_sig: proof.witness.w1.w2,
        cred_counter_less_than_max_accounts,
    };

    let info = UnsignedCredentialDeploymentInfo {
        values: cred_values,
        proofs: id_proofs,
    };
    Ok((info, commitment_rands))
}

#[allow(clippy::too_many_arguments)]
fn compute_pok_sig<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    commitment_key: &PedersenKey<C>,
    commitments: &CredentialDeploymentCommitments<C>,
    commitment_rands: &CommitmentsRandomness<C>,
    id_cred_sec: &Value<C>,
    prf_key: &prf::SecretKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    threshold: Threshold,
    ar_list: &BTreeSet<ArIdentity>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    blinded_sig: &ps_sig::BlindedSignature<P>,
    blind_rand: ps_sig::BlindingRandomness<P>,
) -> anyhow::Result<(com_eq_sig::ComEqSig<P, C>, com_eq_sig::ComEqSigSecret<P, C>)> {
    let att_vec = &alist.alist;
    // number of user chosen attributes (+4 is for tags, valid_to, created_at,
    // max_accounts)
    let num_user_attributes = att_vec.len() + 4;
    // To these there are always two attributes (idCredSec and prf key) added.
    let num_total_attributes = num_user_attributes + 2;
    let ar_scalars = match utils::encode_ars(ar_list) {
        Some(x) => x,
        None => bail!("Cannot encode anonymity revokers."),
    };
    let num_ars = ar_scalars.len(); // we commit to each anonymity revoker, with randomness 0
                                    // and finally we also commit to the anonymity revocation threshold.
                                    // so the total number of commitments is as follows
    let num_total_commitments = num_total_attributes + num_ars + 1;

    let y_tildas = &ip_pub_key.y_tildas;

    ensure!(
        y_tildas.len() > att_vec.len() + num_ars + 5,
        "The PS key must be long enough to accommodate all the attributes"
    );

    ensure!(
        y_tildas.len() >= num_total_attributes,
        "Too many attributes {} >= {}",
        y_tildas.len(),
        num_total_attributes
    );

    let mut gxs = Vec::with_capacity(num_total_commitments);

    let mut secrets = Vec::with_capacity(num_total_commitments);
    secrets.push((
        id_cred_sec.clone(),
        commitment_rands.id_cred_sec_rand.clone(),
    ));
    gxs.push(y_tildas[0]);
    secrets.push((prf_key.to_value(), commitment_rands.prf_rand.clone()));
    gxs.push(y_tildas[1]);

    let public_vals =
        utils::encode_public_credential_values(alist.created_at, alist.valid_to, threshold)?;

    // commitment randomness (0) for the public parameters.
    let zero = PedersenRandomness::<C>::zero();
    secrets.push((Value::new(public_vals), zero.clone()));
    gxs.push(y_tildas[2]);
    for i in 3..num_ars + 3 {
        // the encoded id revoker are commited with randomness 0.
        secrets.push((Value::new(ar_scalars[i - 3]), zero.clone()));
        gxs.push(y_tildas[i]);
    }

    let att_rands = &commitment_rands.attributes_rand;

    let tags_val = utils::encode_tags(alist.alist.keys())?;
    let tags_cmm = commitment_key.hide_worker(&tags_val, &zero);

    let max_accounts_val = Value::new(C::scalar_from_u64(alist.max_accounts.into()));
    let max_accounts_cmm =
        commitment_key.hide(&max_accounts_val, &commitment_rands.max_accounts_rand);

    secrets.push((Value::new(tags_val), zero.clone()));
    gxs.push(y_tildas[num_ars + 3]);
    secrets.push((max_accounts_val, commitment_rands.max_accounts_rand.clone()));
    gxs.push(y_tildas[num_ars + 4]);

    // NB: It is crucial here that we use a btreemap. This guarantees that
    // the att_vec.iter() iterator is ordered by keys.
    for (&g, (tag, v)) in y_tildas.iter().skip(num_ars + 3 + 1).zip(att_vec.iter()) {
        secrets.push((
            Value::new(v.to_field_element()),
            // if we commited with non-zero randomness get it.
            // otherwise we must have commited with zero randomness
            // which we should use
            att_rands.get(tag).cloned().unwrap_or_else(|| zero.clone()),
        ));
        gxs.push(g);
    }

    let mut comm_vec = Vec::with_capacity(num_total_commitments);
    let cmm_id_cred_sec = commitments.cmm_id_cred_sec_sharing_coeff[0];
    comm_vec.push(cmm_id_cred_sec);
    comm_vec.push(commitments.cmm_prf);

    // add commitment to threshold with randomness 0
    comm_vec.push(commitment_key.hide_worker(&public_vals, &zero));

    // and all commitments to ARs with randomness 0
    for ar in ar_scalars.iter() {
        comm_vec.push(commitment_key.hide_worker(ar, &zero));
    }

    comm_vec.push(tags_cmm);
    comm_vec.push(max_accounts_cmm);

    for (idx, v) in alist.alist.iter() {
        match commitments.cmm_attributes.get(idx) {
            None => {
                // need to commit with randomness 0
                let value = Value::<C>::new(v.to_field_element());
                let cmm = commitment_key.hide(&value, &zero);
                comm_vec.push(cmm);
            }
            Some(cmm) => comm_vec.push(*cmm),
        }
    }

    let secret = com_eq_sig::ComEqSigSecret {
        blind_rand,
        values_and_rands: secrets,
    };
    let prover = com_eq_sig::ComEqSig {
        blinded_sig: blinded_sig.clone(),
        commitments: comm_vec,
        // FIXME: Figure out how to get rid of the clone
        ps_pub_key:  ip_pub_key.clone(),
        comm_key:    *commitment_key,
    };
    Ok((prover, secret))
}

/// Computing the commitments for the credential deployment info. We only
/// compute commitments for values that are not revealed as part of the policy.
/// For the other values the verifier (the chain) will compute commitments with
/// randomness 0 in order to verify knowledge of the signature.
#[allow(clippy::too_many_arguments)]
pub fn compute_commitments<C: Curve, AttributeType: Attribute<C::Scalar>, R: Rng>(
    commitment_key: &PedersenKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    prf_key: &prf::SecretKey<C>,
    cred_counter: u8,
    cmm_id_cred_sec_sharing_coeff: &[Commitment<C>],
    cmm_coeff_randomness: Vec<PedersenRandomness<C>>,
    policy: &Policy<C, AttributeType>,
    secret_data: &impl HasAttributeRandomness<C>,
    csprng: &mut R,
) -> anyhow::Result<(CredentialDeploymentCommitments<C>, CommitmentsRandomness<C>)> {
    let id_cred_sec_rand = if let Some(v) = cmm_coeff_randomness.first() {
        v.clone()
    } else {
        bail!("Commitment randomness is an empty vector.");
    };

    let (cmm_prf, prf_rand) = commitment_key.commit(&prf_key, csprng);

    let cred_counter = Value::<C>::new(C::scalar_from_u64(u64::from(cred_counter)));
    let (cmm_cred_counter, cred_counter_rand) = commitment_key.commit(&cred_counter, csprng);
    let max_accounts = Value::<C>::new(C::scalar_from_u64(u64::from(alist.max_accounts)));
    let (cmm_max_accounts, max_accounts_rand) = commitment_key.commit(&max_accounts, csprng);
    let att_vec = &alist.alist;
    let n = att_vec.len();
    // only commitments to attributes which are not revealed.
    ensure!(
        n >= policy.policy_vec.len(),
        "Attribute list is shorter than the number of revealed items in the policy."
    );
    let cmm_len = n - policy.policy_vec.len();
    let mut cmm_attributes = BTreeMap::new();
    let mut attributes_rand = HashMap::with_capacity(cmm_len);
    for (&i, val) in att_vec.iter() {
        // in case the value is openened there is no need to hide it.
        // We can just commit with randomness 0.
        if !policy.policy_vec.contains_key(&i) {
            let value = Value::<C>::new(val.to_field_element());
            let attr_rand = secret_data.get_attribute_commitment_randomness(i)?;
            let cmm = commitment_key.hide(&value, &attr_rand);
            cmm_attributes.insert(i, cmm);
            attributes_rand.insert(i, attr_rand);
        }
    }
    let cdc = CredentialDeploymentCommitments {
        cmm_prf,
        cmm_cred_counter,
        cmm_max_accounts,
        cmm_attributes,
        cmm_id_cred_sec_sharing_coeff: cmm_id_cred_sec_sharing_coeff.to_owned(),
    };

    let cr = CommitmentsRandomness {
        id_cred_sec_rand,
        prf_rand,
        cred_counter_rand,
        max_accounts_rand,
        attributes_rand,
    };
    Ok((cdc, cr))
}

/// proof of knowledge of registration id
#[allow(clippy::too_many_arguments)]
fn compute_pok_reg_id<C: Curve>(
    on_chain_commitment_key: &PedersenKey<C>,
    prf_key: prf::SecretKey<C>,
    cmm_prf: &Commitment<C>,
    prf_rand: &PedersenRandomness<C>,
    cred_counter: u8,
    cmm_cred_counter: &Commitment<C>,
    cred_counter_rand: &PedersenRandomness<C>,
    // max_accounts_rand is not used at the moment.
    // it should be used for the range proof that cred_counter < max_accounts, but
    // that is not yet available
    _max_accounts_rand: &PedersenRandomness<C>,
    reg_id_exponent: C::Scalar,
    reg_id: C,
) -> (com_mult::ComMult<C>, com_mult::ComMultSecret<C>) {
    // Commitment to 1 with randomness 0, to serve as the right-hand side in
    // com_mult proof.
    // NOTE: In order for this to work the reg_id must be computed
    // with the same base as the first element of the commitment key.
    let cmm_one = on_chain_commitment_key.hide(
        &Value::<C>::new(C::Scalar::one()),
        &PedersenRandomness::zero(),
    );

    // commitments are the public values. They all have to
    let public = [
        cmm_prf.combine(cmm_cred_counter),
        Commitment(reg_id),
        cmm_one,
    ];
    // finally the secret keys are derived from actual commited values
    // and the randomness.

    let mut k = C::scalar_from_u64(u64::from(cred_counter));
    k.add_assign(&prf_key);

    // combine the two randomness witnesses
    let mut rand_1 = C::Scalar::zero();
    rand_1.add_assign(prf_rand);
    rand_1.add_assign(cred_counter_rand);
    // reg_id is the commitment to reg_id_exponent with randomness 0
    // the right-hand side of the equation is commitment to 1 with randomness 0
    let values = [Value::new(k), Value::new(reg_id_exponent)];
    let rands = [
        PedersenRandomness::new(rand_1),
        PedersenRandomness::zero(),
        PedersenRandomness::zero(),
    ];

    let secret = com_mult::ComMultSecret { values, rands };

    let prover = com_mult::ComMult {
        cmms:    public,
        cmm_key: *on_chain_commitment_key,
    };
    (prover, secret)
}

/// Generate a ID recovery request, proving of knowledge of idCredSec.
/// The arguments are
/// - ip_info - Identity provider information containing their ID and
///   verification key that goes in to the protocol context.
/// - context - Global Context containing g such that `idCredPub = g^idCredSec`.
///   Also goes into the protocol context.
/// - id_cred_sec - The secret value idCredSec that only the account holder
///   knows.
/// - timestamp - seconds since the unix epoch. Goes into the protocol context.
pub fn generate_id_recovery_request<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    ip_info: &IpInfo<P>,
    context: &GlobalContext<C>,
    id_cred_sec: &Value<C>,
    timestamp: u64, // seconds since the unix epoch
) -> Option<IdRecoveryRequest<C>> {
    let g = context.on_chain_commitment_key.g;
    let id_cred_pub = g.mul_by_scalar(id_cred_sec);
    let prover = dlog::Dlog::<C> {
        public: id_cred_pub,
        coeff:  g,
    };
    let secret = dlog::DlogSecret {
        secret: id_cred_sec.clone(),
    };

    let mut csprng = thread_rng();
    let mut transcript = RandomOracle::domain("IdRecoveryProof");
    transcript.append_message(b"ctx", &context);
    transcript.append_message(b"timestamp", &timestamp);
    transcript.append_message(b"ipIdentity", &ip_info.ip_identity);
    transcript.append_message(b"ipVerifyKey", &ip_info.ip_verify_key);
    let proof = prove(&mut transcript, &prover, secret, &mut csprng)?;
    Some(IdRecoveryRequest {
        id_cred_pub,
        timestamp,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{constants::*, identity_provider::*, secret_sharing::Threshold, test::*};
    use crypto_common::types::{KeyIndex, KeyPair};
    use curve_arithmetic::Curve;
    use either::Either::Left;
    use pedersen_scheme::CommitmentKey as PedersenKey;

    type ExampleCurve = pairing::bls12_381::G1;

    const EXPIRY: TransactionTime = TransactionTime {
        seconds: 111111111111111111,
    };

    // Construct PIO, test various proofs are valid
    // #[test]
    // pub fn test_pio_correctness() {
    // let mut csprng = thread_rng();
    //
    // Create IP info
    // let max_attrs = 10;
    // let num_ars = 4;
    // let (
    // IpData {
    // public_ip_info: ip_info,
    // ip_secret_key: _,
    // metadata: _,
    // },
    // _,
    // ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
    // let aci = test_create_aci(&mut csprng);
    // let (context, pio, _) = test_create_pio(&aci, &ip_info, num_ars);
    //
    // Check id_cred_pub is correct
    // let id_cred_sec = aci.cred_holder_info.id_cred.id_cred_sec.value;
    // let id_cred_pub = ip_info.ip_ars.ar_base.mul_by_scalar(&id_cred_sec);
    // assert_eq!(pio.id_cred_pub, id_cred_pub);
    //
    // Check proof_com_eq_sc is valid
    // let sc_ck = PedersenKey(
    // context.ip_info.ip_verify_key.ys[0],
    // context.ip_info.ip_verify_key.g,
    // );
    // let proof_com_eq_sc_valid = com_eq::verify_com_eq_single(
    // RandomOracle::empty(),
    // &pio.cmm_sc,
    // &pio.id_cred_pub,
    // &sc_ck,
    // &ip_info.ip_ars.ar_base,
    // &pio.proof_com_eq_sc,
    // );
    // assert!(proof_com_eq_sc_valid, "proof_com_eq_sc is not valid");
    //
    // Check ip_ar_data is valid (could use more checks)
    // assert_eq!(
    // pio.ip_ar_data.len() as u8,
    // num_ars - 1,
    // "ip_ar_data has wrong length"
    // );
    //
    // Check pok_sc is valid
    // let pok_sc_valid = dlog::verify_dlog(
    // RandomOracle::empty(),
    // &ip_info.ip_ars.ar_base,
    // &id_cred_pub,
    // &pio.pok_sc,
    // );
    // assert!(pok_sc_valid, "proof_sc is not valid");
    //
    // Check proof_com_eq is valid
    // let commitment_key_prf = PedersenKey(
    // context.ip_info.ip_verify_key.ys[1],
    // context.ip_info.ip_verify_key.g,
    // );
    // let proof_com_eq_valid = com_eq_different_groups::verify_com_eq_diff_grps(
    // RandomOracle::empty(),
    // &pio.cmm_prf,
    // &pio.cmm_prf_sharing_coeff[0],
    // &commitment_key_prf,
    // &context.ip_info.ip_ars.ar_cmm_key,
    // &pio.proof_com_eq,
    // );
    // assert!(proof_com_eq_valid, "proof_com_eq is not valid");
    // }

    #[test]
    pub fn test_compute_sharing_data() {
        use curve_arithmetic::secret_value::Value;

        let mut csprng = thread_rng();

        // Arrange
        let num_ars = 4;
        let threshold = 3;
        let ar_base = ExampleCurve::generate(&mut csprng);
        let (ars_infos, _ar_keys) = test_create_ars(&ar_base, num_ars, &mut csprng);
        let ck = PedersenKey::generate(&mut csprng);
        let value = Value::<ExampleCurve>::generate(&mut csprng);

        // Act
        let (ar_datas, _comms, _rands) =
            compute_sharing_data(&value, &ars_infos, Threshold(threshold), &ck);

        // Assert ArData's are good
        for data in ar_datas.iter() {
            // Add check of encrypted_share and encrypted_randomness
            let cmm_ok = ck.open(
                &data.share,
                &data.randomness_cmm_to_share,
                &data.cmm_to_share,
            );
            assert!(cmm_ok, "ArData cmm_to_share is not valid");
            // assert_eq!(
            //     data.ar_public_key, data.ar_public_key,
            //     "ArData ar_public_key is invalid"
            // );
        }

        // Add check of commitment to polynomial coefficients and randomness
        // encodes value
    }

    /// This test generates a CDI and check values were set correct.
    /// It does not yet test the proofs for correct-/soundness.
    #[test]
    pub fn test_create_credential() {
        // Create IP info with threshold = num_ars - 1
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ip_cdi_secret_key,
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let id_use_data = test_create_id_use_data(&mut csprng);
        let acc_data = InitialAccountData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
                keys
            },
            threshold: SignatureThreshold(2),
        };
        let global_ctx = GlobalContext::<ExampleCurve>::generate(String::from("genesis_string"));

        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);
        let (context, pio, _) = test_create_pio(
            &id_use_data,
            &ip_info,
            &ars_infos,
            &global_ctx,
            num_ars,
            &acc_data,
        );
        let alist = test_create_attributes();
        let ver_ok = verify_credentials(
            &pio,
            context,
            &alist,
            EXPIRY,
            &ip_secret_key,
            &ip_cdi_secret_key,
        );
        let (ip_sig, _) = ver_ok.unwrap();

        // Create CDI arguments
        let id_object = IdentityObject {
            pre_identity_object: pio,
            alist,
            signature: ip_sig,
        };
        let valid_to = YearMonth::new(2022, 5).unwrap(); // May 2022
        let created_at = YearMonth::new(2020, 5).unwrap(); // May 2020
        let policy = Policy {
            valid_to,
            created_at,
            policy_vec: {
                let mut tree = BTreeMap::new();
                tree.insert(AttributeTag::from(8u8), AttributeKind::from(31));
                tree
            },
            _phantom: Default::default(),
        };
        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
        keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
        let sigthres = SignatureThreshold(2);
        let acc_data = CredentialData {
            keys,
            threshold: sigthres,
        };

        let cred_ctr = 42;
        let (cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            cred_ctr,
            policy.clone(),
            &acc_data,
            &SystemAttributeRandomness {},
            &Left(EXPIRY),
        )
        .expect("Could not generate CDI");

        // Check cred_account
        let cred_account_ok = {
            let key_info = cdi.values.cred_key_info;
            key_info.keys.len() == 3 && key_info.threshold == sigthres
        };
        assert!(cred_account_ok, "CDI cred_account is invalid");

        // Check reg_id
        let reg_id_exponent = id_use_data.aci.prf_key.prf_exponent(cred_ctr).unwrap();
        let reg_id = global_ctx
            .on_chain_commitment_key
            .hide(
                &Value::<ExampleCurve>::new(reg_id_exponent),
                &PedersenRandomness::zero(),
            )
            .0;
        assert_eq!(cdi.values.cred_id, reg_id, "CDI reg_id is invalid");

        // Check ip_identity
        assert_eq!(
            cdi.values.ip_identity, ip_info.ip_identity,
            "CDI ip_identity is invalid"
        );

        // Check threshold
        assert_eq!(
            cdi.values.threshold,
            Threshold(num_ars - 1),
            "CDI threshold is invalid"
        );

        // Check ar_data
        assert_eq!(
            cdi.values.ar_data.len() as u8,
            num_ars,
            "CDI ar_data length is invalid"
        );

        // Check policy
        assert_eq!(cdi.values.policy, policy, "CDI policy is invalid");
    }
}
