//! Functionality needed by the identity provider. This gathers together the
//! primitives from the rest of the library into a convenient package.
use crate::{
    secret_sharing::Threshold,
    sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups, common::*, dlog},
    types::*,
    utils,
};
use bulletproofs::range_proof::verify_efficient;
use crypto_common::{to_bytes, types::TransactionTime};
use curve_arithmetic::{multiexp, Curve, Pairing};
use elgamal::multicombine;
use ff::Field;
use pedersen_scheme::{Commitment, CommitmentKey};
use rand::*;
use random_oracle::RandomOracle;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reason for rejecting an identity object request.
/// This is for cryptographic reasons only, real-world identity verification is
/// not handled in this library.
pub enum Reason {
    FailedToVerifyKnowledgeOfIdCredSec,
    FailedToVerifyIdCredSecEquality,
    FailedToVerifyPrfData,
    WrongArParameters,
    IllegalAttributeRequirements,
    TooManyAttributes,
    IncorrectProof,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Reason::*;
        match *self {
            FailedToVerifyKnowledgeOfIdCredSec => {
                write!(f, "Cannot verify knowledge of idCredSec.")
            }
            FailedToVerifyIdCredSecEquality => write!(f, "Cannot verify consistency of idCredSec."),
            FailedToVerifyPrfData => write!(f, "Cannot verify consistency of PRF data."),
            WrongArParameters => write!(f, "Inconsistent anonymity revocation parameters."),
            IllegalAttributeRequirements => write!(f, "Illegal attributes."),
            TooManyAttributes => write!(f, "Too many attributes for the given public key."),
            IncorrectProof => write!(f, "Zero knowledge proof does not verify."),
        }
    }
}

/// The validation of the two versions of identity object requests are very
/// similar, and therefore the common validation parts of the two flows are
/// factored out in the function `validate_request_common`. It produces the
/// common sigma protocol verifier and witnesses that are used in both
/// `validate_request` and `validate_request_v1`:
/// * In the version 0 flow, the common verifier is AND'ed with a verifier
///   checking that RegID = PRF(key_PRF, 0)
/// * In the version 1 flow, the sigma protocol verifier is the common verifier.
/// The function also verifies the bulletproofs range rangeproof.

/// Validate all the proofs in a version 0 identity object request. This is for
/// the flow, where an initial account is created together with the identity.
pub fn validate_request<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    pre_id_obj: &PreIdentityObject<P, C>,
    context: IpContext<P, C>,
) -> Result<(), Reason> {
    let pub_info_for_ip = &pre_id_obj.pub_info_for_ip;
    let id_cred_pub = &pre_id_obj.pub_info_for_ip.id_cred_pub;
    let poks_common = &pre_id_obj.poks.common_proof_fields;
    let proof_acc_sk = &pre_id_obj.poks.proof_acc_sk;
    // Verify signature:
    let keys = &pub_info_for_ip.vk_acc.keys;
    let threshold = pub_info_for_ip.vk_acc.threshold;

    // message signed
    let signed = Sha256::digest(&to_bytes(&pub_info_for_ip));

    // Notice that here we provide all the verification keys, and the
    // function `verify_accunt_ownership_proof` assumes that
    // we have as many signatures as verification keys.
    if !utils::verify_account_ownership_proof(keys, threshold, proof_acc_sk, signed.as_ref()) {
        return Err(Reason::IncorrectProof);
    }

    let mut transcript = RandomOracle::domain("PreIdentityProof");
    // Construct the common verifier and verify the range proof
    let (verifier, witness) = validate_request_common(
        &mut transcript,
        id_cred_pub,
        pre_id_obj.get_common_pio_fields(),
        poks_common,
        context,
    )?;

    // Additionally verify that RegID = PRF(key_PRF, 0):
    let verifier_prf_regid = com_eq::ComEq {
        commitment: pre_id_obj.cmm_prf,
        y:          context.global_context.on_chain_commitment_key.g,
        g:          pub_info_for_ip.reg_id,
        cmm_key:    verifier.first.second.cmm_key_1,
    };
    let prf_regid_witness = pre_id_obj.poks.prf_regid_proof.clone();

    let verifier = verifier.add_prover(verifier_prf_regid);
    // Construct the witness consisting of the common witness and the
    // prf_regid_witness above.
    let witness = AndWitness {
        w1: witness,
        w2: prf_regid_witness,
    };
    let proof = SigmaProof {
        challenge: poks_common.challenge,
        witness,
    };

    // Verify the sigma protocol proof
    if verify(&mut transcript, &verifier, &proof) {
        Ok(())
    } else {
        Err(Reason::IncorrectProof)
    }
}

/// Validate all the proofs in a version 1 identity object request. This is for
/// the flow, where no initial account creation is involved.
pub fn validate_request_v1<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    pre_id_obj: &PreIdentityObjectV1<P, C>,
    context: IpContext<P, C>,
) -> Result<(), Reason> {
    let id_cred_pub = &pre_id_obj.id_cred_pub;
    let common_fields = pre_id_obj.get_common_pio_fields();
    let poks_common = &pre_id_obj.poks;

    let mut transcript = RandomOracle::domain("PreIdentityProof");
    // Construct the common verifier and verify the range proof
    let (verifier, witness) = validate_request_common(
        &mut transcript,
        id_cred_pub,
        common_fields,
        poks_common,
        context,
    )?;
    let proof = SigmaProof {
        challenge: poks_common.challenge,
        witness,
    };
    // Verify the sigma protocol proof
    if verify(&mut transcript, &verifier, &proof) {
        Ok(())
    } else {
        Err(Reason::IncorrectProof)
    }
}

/// Type alias for sigma protocol verifier needed by both `validate_request` and
/// `validate_request_v1`.
type CommonPioVerifierType<P, C> = AndAdapter<
    AndAdapter<
        AndAdapter<dlog::Dlog<C>, com_eq::ComEq<C, <P as Pairing>::G1>>,
        com_eq_different_groups::ComEqDiffGroups<<P as Pairing>::G1, C>,
    >,
    ReplicateAdapter<com_enc_eq::ComEncEq<C>>,
>;

type CommonVerifierWithWitness<P, C> = (
    CommonPioVerifierType<P, C>,
    <CommonPioVerifierType<P, C> as SigmaProtocol>::ProverWitness,
);

/// This is used by both `validate_request` and `validate_request_v1` to
/// construct the sigma protocol verifier and witness used by both of these
/// functions. The inputs are
/// - transcript - the RandomOracle used in the protocol.
/// - id_cred_pub - the IdCredPub of the user behind the identity.
/// - common_fields - relevant information used to verify proofs.
/// - poks_common - the challenge, the common sigma protocol witnesses together
///   with the range proof.
/// - context - the identity provider context
fn validate_request_common<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    transcript: &mut RandomOracle,
    id_cred_pub: &C,
    common_fields: CommonPioFields<P, C>,
    poks_common: &CommonPioProofFields<P, C>,
    context: IpContext<P, C>,
) -> Result<CommonVerifierWithWitness<P, C>, Reason> {
    // Verify proof:
    let ip_info = &context.ip_info;
    let commitment_key_sc = CommitmentKey {
        g: ip_info.ip_verify_key.ys[0],
        h: ip_info.ip_verify_key.g,
    };
    let commitment_key_prf = CommitmentKey {
        g: ip_info.ip_verify_key.ys[1],
        h: ip_info.ip_verify_key.g,
    };
    transcript.append_message(b"ctx", &context.global_context);
    transcript.append_message(b"choice_ar_parameters", common_fields.choice_ar_parameters);
    transcript.append_message(b"cmm_sc", common_fields.cmm_sc);
    transcript.append_message(b"cmm_prf", common_fields.cmm_prf);
    transcript.append_message(
        b"cmm_prf_sharing_coeff",
        common_fields.cmm_prf_sharing_coeff,
    );

    let id_cred_sec_verifier = dlog::Dlog {
        public: *id_cred_pub,
        coeff:  context.global_context.on_chain_commitment_key.g,
    };
    let id_cred_sec_witness = poks_common.id_cred_sec_witness;

    // Verify that id_cred_sec is the same both in id_cred_pub and in cmm_sc
    let id_cred_sec_eq_verifier = com_eq::ComEq {
        commitment: *common_fields.cmm_sc,
        y:          *id_cred_pub,
        cmm_key:    commitment_key_sc,
        g:          context.global_context.on_chain_commitment_key.g,
    };

    // TODO: Figure out whether we can somehow get rid of this clone.
    let id_cred_sec_eq_witness = poks_common.commitments_same_proof.clone();

    let choice_ar_handles = common_fields.choice_ar_parameters.ar_identities.clone();
    let revocation_threshold = common_fields.choice_ar_parameters.threshold;

    let number_of_ars = choice_ar_handles.len();
    // We have to have at least one anonymity revoker, and the threshold.
    // Revocation threshold is always at least 1 by the data type definition and
    // serialization implementation.
    // Thus strictly speaking the first part of the check is redundant, but
    // it does not hurt.
    let rt_usize: usize = revocation_threshold.into();
    if number_of_ars == 0 || rt_usize > number_of_ars {
        return Err(Reason::WrongArParameters);
    }

    // Check that the set of ArIdentities and the encryptions in ip_ar_data are
    // actually the same. This is awkward, and choice_ar_handles is no longer
    // necessary, but removing it would break backwards compatibility. So we
    // instead have to check that the set is equal to some other given set.
    // Later on we check whether all the listed ARs actually exist in the context.
    if number_of_ars != common_fields.ip_ar_data.len() {
        return Err(Reason::WrongArParameters);
    }
    if common_fields
        .ip_ar_data
        .keys()
        .zip(common_fields.choice_ar_parameters.ar_identities.iter())
        .any(|(k1, k2)| k1 != k2)
    {
        return Err(Reason::WrongArParameters);
    }

    // We also need to check that the threshold is actually equal to
    // the number of coefficients in the sharing polynomial
    // (corresponding to the degree+1)
    if rt_usize != common_fields.cmm_prf_sharing_coeff.len() {
        return Err(Reason::WrongArParameters);
    }

    // ar commitment key
    let ar_ck = &context.global_context.on_chain_commitment_key;

    // The commitment to the PRF key to the identity providers
    // must have at least one value.
    // FIXME: Rework the choice of data-structure so that this is implicit.
    if common_fields.cmm_prf_sharing_coeff.is_empty() {
        return Err(Reason::WrongArParameters);
    }

    // Verify that the two commitments to the PRF key are the same.
    let verifier_prf_same = com_eq_different_groups::ComEqDiffGroups {
        commitment_1: *common_fields.cmm_prf,
        commitment_2: *common_fields
            .cmm_prf_sharing_coeff
            .first()
            .expect("Precondition checked."),
        cmm_key_1:    commitment_key_prf,
        cmm_key_2:    *ar_ck,
    };
    let witness_prf_same = poks_common.commitments_prf_same;

    let h_in_exponent = *context.global_context.encryption_in_exponent_generator();
    let prf_verification = compute_prf_sharing_verifier(
        ar_ck,
        common_fields.cmm_prf_sharing_coeff,
        common_fields.ip_ar_data,
        context.ars_infos,
        &h_in_exponent,
    );
    let (prf_sharing_verifier, prf_sharing_witness) = match prf_verification {
        Some(v) => v,
        None => return Err(Reason::WrongArParameters),
    };

    let verifier = AndAdapter {
        first:  id_cred_sec_verifier,
        second: id_cred_sec_eq_verifier,
    };
    let verifier = verifier
        .add_prover(verifier_prf_same)
        .add_prover(prf_sharing_verifier);

    for ((ar_identity, ar_data), proof) in common_fields
        .ip_ar_data
        .iter()
        .zip(poks_common.bulletproofs.iter())
    {
        let ciphers = ar_data.enc_prf_key_share;
        let ar_info = match context.ars_infos.get(ar_identity) {
            Some(x) => x,
            None => return Err(Reason::IncorrectProof),
        };
        let pk: C = ar_info.ar_public_key.key;
        let keys: CommitmentKey<C> = CommitmentKey {
            g: h_in_exponent,
            h: pk,
        };
        let gens = &context.global_context.bulletproof_generators().take(32 * 8);
        let commitments = ciphers.iter().map(|x| Commitment(x.1)).collect::<Vec<_>>();
        transcript.append_message(b"encrypted_share", &ciphers);
        if verify_efficient(transcript, 32, &commitments, proof, gens, &keys).is_err() {
            return Err(Reason::IncorrectProof);
        }
    }

    transcript.append_message(b"bulletproofs", &poks_common.bulletproofs);
    let witness = AndWitness {
        w1: AndWitness {
            w1: AndWitness {
                w1: id_cred_sec_witness,
                w2: id_cred_sec_eq_witness,
            },
            w2: witness_prf_same,
        },
        w2: prf_sharing_witness,
    };
    Ok((verifier, witness))
}

/// Sign the given pre-identity-object to produce a version 0 identity object.
/// The inputs are
/// - pre_id_obj - The version 0 pre-identity object
/// - ip_info - Information about the identity provider, including its public
///   keys
/// - alist - the list of attributes to be signed
/// - ip_secret_key - the signing key of the identity provider
pub fn sign_identity_object<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObject<P, C>,
    ip_info: &IpInfo<P>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Reason> {
    sign_identity_object_common(
        &pre_id_obj.get_common_pio_fields(),
        ip_info,
        alist,
        ip_secret_key,
    )
}

/// Sign the given pre-identity-object to produce a version 1 identity object.
/// The inputs are
/// - pre_id_obj - The version 1 pre-identity object
/// - ip_info - Information about the identity provider, including its public
///   keys
/// - alist - the list of attributes to be signed
/// - ip_secret_key - the signing key of the identity provider
pub fn sign_identity_object_v1<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObjectV1<P, C>,
    ip_info: &IpInfo<P>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Reason> {
    sign_identity_object_common(
        &pre_id_obj.get_common_pio_fields(),
        ip_info,
        alist,
        ip_secret_key,
    )
}

/// Sign the message constructed from the common fields of a pre-identity object
/// and the attribute list. The signature is to be used in a identity object.
/// The inputs are
/// - common_fields - The common fields of a pre-identity object
/// - ip_info - Information about the identity provider, including its public
///   keys
/// - alist - the list of attributes to be signed
/// - ip_secret_key - the signing key of the identity provider
fn sign_identity_object_common<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    common_fields: &CommonPioFields<P, C>,
    ip_info: &IpInfo<P>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Reason> {
    let choice_ar_handles = common_fields.choice_ar_parameters.ar_identities.clone();
    let message: ps_sig::UnknownMessage<P> = compute_message(
        common_fields.cmm_prf,
        common_fields.cmm_sc,
        common_fields.choice_ar_parameters.threshold,
        &choice_ar_handles,
        alist,
        &ip_info.ip_verify_key,
    )?;
    let mut csprng = thread_rng();
    // FIXME: Pass in csprng here.
    Ok(ip_secret_key.sign_unknown_message(&message, &mut csprng))
}

fn compute_prf_sharing_verifier<C: Curve>(
    ar_commitment_key: &CommitmentKey<C>,
    cmm_sharing_coeff: &[Commitment<C>],
    ip_ar_data: &BTreeMap<ArIdentity, IpArData<C>>,
    known_ars: &BTreeMap<ArIdentity, ArInfo<C>>,
    encryption_in_exponent_generator: &C,
) -> Option<IdCredPubVerifiers<C>> {
    let mut verifiers = Vec::with_capacity(ip_ar_data.len());
    let mut witnesses = Vec::with_capacity(ip_ar_data.len());

    for (ar_id, ar_data) in ip_ar_data.iter() {
        let cmm_share = utils::commitment_to_share(&ar_id.to_scalar::<C>(), cmm_sharing_coeff);
        // finding the right encryption key

        // Take linear combination of ciphers
        let u8_chunk_size = u8::from(CHUNK_SIZE);
        let two_chunksize = C::scalar_from_u64(1 << u8_chunk_size);
        let mut power_of_two = C::Scalar::one();

        let mut scalars = Vec::with_capacity(ar_data.enc_prf_key_share.len());
        for _ in 0..ar_data.enc_prf_key_share.len() {
            scalars.push(power_of_two);
            power_of_two.mul_assign(&two_chunksize);
        }
        let combined_ciphers = multicombine(&ar_data.enc_prf_key_share, &scalars);

        let ar_info = known_ars.get(ar_id)?;
        let verifier = com_enc_eq::ComEncEq {
            cipher: combined_ciphers,
            commitment: cmm_share,
            pub_key: ar_info.ar_public_key,
            cmm_key: *ar_commitment_key,
            encryption_in_exponent_generator: *encryption_in_exponent_generator,
        };
        verifiers.push(verifier);
        // TODO: Figure out whether we can somehow get rid of this clone.
        witnesses.push(ar_data.proof_com_enc_eq.clone())
    }
    Some((
        ReplicateAdapter {
            protocols: verifiers,
        },
        ReplicateWitness { witnesses },
    ))
}

/// Validate the request and sign the version 0 identity object.
pub fn verify_credentials<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObject<P, C>,
    context: IpContext<P, C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    expiry: TransactionTime,
    ip_secret_key: &ps_sig::SecretKey<P>,
    ip_cdi_secret_key: &ed25519_dalek::SecretKey,
) -> Result<
    (
        ps_sig::Signature<P>,
        InitialCredentialDeploymentInfo<C, AttributeType>,
    ),
    Reason,
> {
    validate_request(pre_id_obj, context)?;
    let sig = sign_identity_object(pre_id_obj, context.ip_info, alist, ip_secret_key)?;
    let initial_cdi = create_initial_cdi(
        context.ip_info,
        pre_id_obj.pub_info_for_ip.clone(),
        alist,
        expiry,
        ip_cdi_secret_key,
    );
    Ok((sig, initial_cdi))
}

/// Validate the request and sign the version 1 identity object.
pub fn verify_credentials_v1<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObjectV1<P, C>,
    context: IpContext<P, C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Reason> {
    validate_request_v1(pre_id_obj, context)?;
    let sig = sign_identity_object_v1(pre_id_obj, context.ip_info, alist, ip_secret_key)?;
    Ok(sig)
}

/// Produce a signature on the initial account data to make a message that is
/// submitted to the chain to create an initial account.
pub fn create_initial_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    ip_info: &IpInfo<P>,
    pub_info_for_ip: PublicInformationForIp<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    expiry: TransactionTime,
    ip_cdi_secret_key: &ed25519_dalek::SecretKey,
) -> InitialCredentialDeploymentInfo<C, AttributeType> {
    // The initial policy is empty, apart from the expiry date of the credential.
    let policy: Policy<C, AttributeType> = Policy {
        valid_to:   alist.valid_to,
        created_at: alist.created_at,
        policy_vec: BTreeMap::new(),
        _phantom:   Default::default(),
    };
    let cred_values = InitialCredentialDeploymentValues {
        reg_id: pub_info_for_ip.reg_id,
        ip_identity: ip_info.ip_identity,
        policy,
        cred_account: pub_info_for_ip.vk_acc,
    };

    let sig = sign_initial_cred_values(&cred_values, expiry, ip_info, ip_cdi_secret_key);
    InitialCredentialDeploymentInfo {
        values: cred_values,
        sig,
    }
}

fn sign_initial_cred_values<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    initial_cred_values: &InitialCredentialDeploymentValues<C, AttributeType>,
    expiry: TransactionTime,
    ip_info: &IpInfo<P>,
    ip_cdi_secret_key: &ed25519_dalek::SecretKey,
) -> IpCdiSignature {
    let mut hasher = Sha256::new();
    hasher.update(&to_bytes(&expiry));
    hasher.update(&to_bytes(&initial_cred_values));
    let to_sign = hasher.finalize();
    let expanded_sk = ed25519_dalek::ExpandedSecretKey::from(ip_cdi_secret_key);
    expanded_sk
        .sign(to_sign.as_ref(), &ip_info.ip_cdi_verify_key)
        .into()
}

pub fn compute_message<P: Pairing, AttributeType: Attribute<P::ScalarField>>(
    cmm_prf: &Commitment<P::G1>,
    cmm_sc: &Commitment<P::G1>,
    threshold: Threshold,
    ar_list: &BTreeSet<ArIdentity>,
    att_list: &AttributeList<P::ScalarField, AttributeType>,
    ps_public_key: &ps_sig::PublicKey<P>,
) -> Result<ps_sig::UnknownMessage<P>, Reason> {
    let max_accounts = P::G1::scalar_from_u64(att_list.max_accounts.into());

    let tags = {
        match utils::encode_tags(att_list.alist.keys()) {
            Ok(f) => f,
            Err(_) => return Err(Reason::IllegalAttributeRequirements),
        }
    };

    // the list to be signed consists of (in that order)
    // - commitment to idcredsec
    // - commitment to prf key
    // - created_at and valid_to dates of the attribute list
    // - encoding of anonymity revokers.
    // - tags of the attribute list
    // - attribute list elements

    let ar_encoded = match utils::encode_ars(ar_list) {
        Some(x) => x,
        None => return Err(Reason::WrongArParameters),
    };

    let att_vec = &att_list.alist;
    let m = ar_encoded.len();
    let n = att_vec.len();
    let key_vec = &ps_public_key.ys;

    if key_vec.len() < n + m + 5 {
        return Err(Reason::TooManyAttributes);
    }

    let mut gs = Vec::with_capacity(1 + m + 2 + n);
    let mut exps = Vec::with_capacity(1 + m + 2 + n);

    // The error here should never happen, but it is safe to just propagate it if it
    // does by any chance.
    let public_params =
        utils::encode_public_credential_values(att_list.created_at, att_list.valid_to, threshold)
            .map_err(|_| Reason::IllegalAttributeRequirements)?;

    // add valid_to, created_at, threshold.
    gs.push(key_vec[2]);
    exps.push(public_params);

    // and add all anonymity revocation
    for i in 3..(m + 3) {
        let ar_handle = ar_encoded[i - 3];
        gs.push(key_vec[i]);
        exps.push(ar_handle);
    }

    gs.push(key_vec[m + 3]);
    exps.push(tags);

    gs.push(key_vec[m + 3 + 1]);
    exps.push(max_accounts);

    // NB: It is crucial that att_vec is an ordered map and that .values iterator
    // returns messages in order of tags.
    for (&k, v) in key_vec.iter().skip(m + 5).zip(att_vec.values()) {
        let att = v.to_field_element();
        gs.push(k);
        exps.push(att);
    }
    let msg =
        ps_sig::UnknownMessage(multiexp(&gs, &exps).plus_point(&cmm_sc.0.plus_point(&cmm_prf.0)));
    Ok(msg)
}

/// Verify a ID recovery quest containing proof of knowledge of idCredSec. If
/// the proof verifies, the IDP sends the attribute list and the signature to
/// the prover (the account holder). The argument are
/// - ip_info - Identity provider information containing their IR and
///   verification key that goes in to the protocol context.
/// - context - Global Context containing g such that `idCredPub = g^idCredSec`.
///   Also goes into the protocol context.
/// - request - the ID recovery containing idCredPub, a timestamp and a proof of
///   knowledge of idCredSec.
pub fn validate_id_recovery_request<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    ip_info: &IpInfo<P>,
    context: &GlobalContext<C>,
    request: &IdRecoveryRequest<C>,
) -> bool {
    let verifier = dlog::Dlog::<C> {
        public: request.id_cred_pub,
        coeff:  context.on_chain_commitment_key.g,
    };
    let mut transcript = RandomOracle::domain("IdRecoveryProof");
    transcript.append_message(b"ctx", &context);
    transcript.append_message(b"timestamp", &request.timestamp);
    transcript.append_message(b"ipIdentity", &ip_info.ip_identity);
    transcript.append_message(b"ipVerifyKey", &ip_info.ip_verify_key);
    verify(&mut transcript, &verifier, &request.proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account_holder::generate_id_recovery_request, constants::ArCurve, test::*};
    use crypto_common::types::{KeyIndex, KeyPair};
    use ff::Field;
    use pedersen_scheme::{CommitmentKey, Value as PedersenValue};
    use std::collections::btree_map::BTreeMap;

    const EXPIRY: TransactionTime = TransactionTime {
        seconds: 111111111111111111,
    };

    // Eval a polynomial at point.
    fn eval_poly<F: Field, X: AsRef<F>>(coeffs: &[X], x: &F) -> F {
        let mut acc = F::zero();
        for coeff in coeffs.iter().rev() {
            acc.mul_assign(x);
            acc.add_assign(coeff.as_ref());
        }
        acc
    }

    /// Randomized test that commitment_to_share conforms to the specification.
    #[test]
    fn test_commitment_to_share() {
        let mut csprng = thread_rng();
        let ck = CommitmentKey::<ArCurve>::generate(&mut csprng);

        // Make degree-d polynomial
        let d = csprng.gen_range(1, 10);
        let mut coeffs = Vec::new();
        let mut rands = Vec::new();
        let mut values = Vec::new();
        for _i in 0..=d {
            // Make commitments to coefficients
            let v = PedersenValue::<ArCurve>::generate(&mut csprng);
            let (c, r) = ck.commit(&v, &mut csprng);
            coeffs.push(c);
            rands.push(r);
            values.push(v);
        }

        // Sample some random share numbers
        for _ in 0..100 {
            let sh: ArIdentity = ArIdentity::new(std::cmp::max(1, csprng.next_u32()));
            // And evaluate the values and rands at sh.
            let point = sh.to_scalar::<ArCurve>();
            let pv = eval_poly(&values, &point);
            let rv = eval_poly(&rands, &point);

            let p0 = utils::commitment_to_share(&sh.to_scalar::<ArCurve>(), &coeffs);
            assert_eq!(p0, ck.hide_worker(&pv, &rv));
        }
    }

    /// Check IP's verify_credentials succeeds for well-formed data.
    #[test]
    fn test_verify_credentials_success() {
        // Arrange (create identity provider and PreIdentityObject, and verify validity)
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ip_cdi_secret_key,
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);

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
        let (context, pio, _) = test_create_pio(
            &id_use_data,
            &ip_info,
            &ars_infos,
            &global_ctx,
            num_ars,
            &acc_data,
        );
        let attrs = test_create_attributes();

        // Act
        let ver_ok = verify_credentials(
            &pio,
            context,
            &attrs,
            EXPIRY,
            &ip_secret_key,
            &ip_cdi_secret_key,
        );

        // Assert
        assert!(ver_ok.is_ok());
    }

    #[test]
    fn test_verify_credentials_success_v1() {
        // Arrange (create identity provider and PreIdentityObject, and verify validity)
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);

        let id_use_data = test_create_id_use_data(&mut csprng);
        let (context, pio, _) =
            test_create_pio_v1(&id_use_data, &ip_info, &ars_infos, &global_ctx, num_ars);
        let attrs = test_create_attributes();

        // Act
        let ver_ok = verify_credentials_v1(&pio, context, &attrs, &ip_secret_key);

        // Assert
        assert!(ver_ok.is_ok());
    }

    // /// Check IP's verify_credentials fail for wrong id_cred_sec
    // proof-of-knowledge.
    // #[test]
    // fn test_verify_credentials_fail_pok_idcredsec() {
    // Arrange
    // let max_attrs = 10;
    // let num_ars = 4;
    // let mut csprng = thread_rng();
    // let (
    // IpData {
    // public_ip_info: ip_info,
    // ip_secret_key,
    // },
    // _,
    // ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
    // let aci = test_create_aci(&mut csprng);
    // let (_, mut pio, _) = test_create_pio(&aci, &ip_info, num_ars);
    // let attrs = test_create_attributes();
    //
    // Act (make dlog proof use wrong id_cred_sec)
    // let wrong_id_cred_sec = ArCurve::generate_scalar(&mut csprng);
    // pio.pok_sc = prove_dlog(
    // &mut csprng,
    // RandomOracle::empty(),
    // &pio.id_cred_pub,
    // &wrong_id_cred_sec,
    // &ip_info.ip_ars.ar_base,
    // );
    // let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);
    //
    // Assert
    // if sig_ok.is_ok() {
    // assert_eq!(
    // wrong_id_cred_sec,
    // aci.cred_holder_info.id_cred.id_cred_sec.value
    // );
    // }
    // assert_eq!(
    // sig_ok,
    // Err(Reason::FailedToVerifyKnowledgeOfIdCredSec),
    // "Verify_credentials did not fail on invalid IdCredSec PoK"
    // )
    // }

    /// Test IP's verify_credentials fail if discrete log of idcredpub and
    /// elgamal encryption are different
    #[test]
    fn test_verify_credentials_fail_idcredsec_equality() {
        // Arrange
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);
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
        let (ctx, mut pio, _) = test_create_pio(
            &id_use_data,
            &ip_info,
            &ars_infos,
            &global_ctx,
            num_ars,
            &acc_data,
        );
        // let attrs = test_create_attributes();

        // Act (make cmm_sc be comm. of id_cred_sec but with wrong/fresh randomness)
        let sc_ck = CommitmentKey {
            g: ctx.ip_info.ip_verify_key.ys[0],
            h: ctx.ip_info.ip_verify_key.g,
        };
        let id_cred_sec = id_use_data.aci.cred_holder_info.id_cred.id_cred_sec;
        let (cmm_sc, _) = sc_ck.commit(&id_cred_sec, &mut csprng);
        pio.cmm_sc = cmm_sc;
        let ver_ok = validate_request(&pio, ctx);

        // Assert
        assert_eq!(
            ver_ok,
            Err(Reason::IncorrectProof),
            "Verify_credentials did not fail with inconsistent idcredpub and elgamal"
        );
    }

    /// Test IP's verify_credentials fails if the PRF key check fail.
    #[test]
    fn test_verify_credentials_fail_prf_data() {
        // Arrange
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);
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
        let (context, mut pio, _) = test_create_pio(
            &id_use_data,
            &ip_info,
            &ars_infos,
            &global_ctx,
            num_ars,
            &acc_data,
        );
        // let attrs = test_create_attributes();

        // Act (make cmm_prf be a commitment to a wrong/random value)
        let val = curve_arithmetic::Value::<ArCurve>::generate(&mut csprng);
        let (cmm_prf, _) = context
            .global_context
            .on_chain_commitment_key
            .commit(&val, &mut csprng);
        pio.cmm_prf = cmm_prf;
        let ver_ok = validate_request(&pio, context);

        // Assert
        assert_eq!(
            ver_ok,
            Err(Reason::IncorrectProof),
            "Verify_credentials did not fail with invalid PRF commitment"
        );
    }

    #[test]
    fn test_validate_id_recovery_request() {
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let aci = test_create_aci(&mut csprng);

        let timestamp = 1000;
        let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
        let request =
            generate_id_recovery_request(&ip_info, &global_ctx, id_cred_sec, timestamp).unwrap();

        let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
        assert!(result);
    }

    #[test]
    fn test_verify_pok_wrong_id_cred_sec() {
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let aci = test_create_aci(&mut csprng);

        let timestamp = 1000;
        let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
        let id_cred_pub = global_ctx
            .on_chain_commitment_key
            .g
            .mul_by_scalar(id_cred_sec);
        let id_cred_sec_wrong = PedersenValue::generate(&mut csprng);
        let mut request =
            generate_id_recovery_request(&ip_info, &global_ctx, &id_cred_sec_wrong, timestamp)
                .unwrap();

        request.id_cred_pub = id_cred_pub;

        let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
        assert!(
            !result,
            "Verifying pok of idCredSec did not fail with wrong idCredSec"
        );
    }

    #[test]
    fn test_verify_pok_wrong_timestamp() {
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let aci = test_create_aci(&mut csprng);

        let timestamp = 1000;
        let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
        let mut request =
            generate_id_recovery_request(&ip_info, &global_ctx, id_cred_sec, timestamp).unwrap();
        request.timestamp += 1;

        let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
        assert!(
            !result,
            "Verifying pok of idCredSec did not fail with wrong timestamp"
        );
    }

    #[test]
    fn test_verify_pok_wrong_idp_id() {
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: mut ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let aci = test_create_aci(&mut csprng);

        let timestamp = 1000;
        let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
        let request =
            generate_id_recovery_request(&ip_info, &global_ctx, id_cred_sec, timestamp).unwrap();

        ip_info.ip_identity = IpIdentity(1);

        let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
        assert!(
            !result,
            "Verifying pok of idCredSec did not fail with wrong IDP ID"
        );
    }

    #[test]
    fn test_verify_pok_wrong_idp_keys() {
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: mut ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let aci = test_create_aci(&mut csprng);

        let timestamp = 1000;
        let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
        let request =
            generate_id_recovery_request(&ip_info, &global_ctx, id_cred_sec, timestamp).unwrap();

        ip_info.ip_verify_key =
            ps_sig::PublicKey::arbitrary((5 + num_ars + max_attrs) as usize, &mut csprng);

        let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
        assert!(
            !result,
            "Verifying pok of idCredSec did not fail with wrong IDP verify keys"
        );
    }

    #[test]
    fn test_verify_pok_wrong_global_context() {
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let IpData {
            public_ip_info: ip_info,
            ..
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let mut global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
        let aci = test_create_aci(&mut csprng);

        let timestamp = 1000;
        let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
        let request =
            generate_id_recovery_request(&ip_info, &global_ctx, id_cred_sec, timestamp).unwrap();

        global_ctx.genesis_string = String::from("another_string");

        let result = validate_id_recovery_request(&ip_info, &global_ctx, &request);
        assert!(
            !result,
            "Verifying pok of idCredSec did not fail with wrong global context"
        );
    }
}
