//! Functionality to prove and verify identity attribute credentials based on identity credentials. These are to a large
//! extent equivalent to account credentials deployed on chain, but there is no on-chain account credentials involved.

use super::{account_holder, secret_sharing::*, types::*, utils};
use crate::pedersen_commitment::{CommitmentKey, Randomness};
use crate::random_oracle::StructuredDigest;
use crate::{
    curve_arithmetic::{Curve, Pairing},
    dodis_yampolskiy_prf as prf,
    pedersen_commitment::{
        Commitment, CommitmentKey as PedersenKey, Randomness as PedersenRandomness, Value,
    },
    random_oracle::RandomOracle,
    sigma_protocols::{com_enc_eq, com_eq_sig, common::*},
};
use anyhow::{bail, ensure};
use core::fmt;
use core::fmt::Display;
use either::Either;
use rand::*;
use std::collections::{btree_map::BTreeMap, BTreeSet};

/// Construct proof for attribute credentials from identity credential
pub fn prove_identity_attributes<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Clone + Attribute<C::Scalar>,
>(
    context: IpContext<'_, P, C>,
    id_object: &impl HasIdentityObjectFields<P, C, AttributeType>,
    id_object_use_data: &IdObjectUseData<P, C>,
    policy: Policy<C, AttributeType>,
    transcript: &mut RandomOracle,
) -> anyhow::Result<(
    IdentityAttributesCredentialsInfo<P, C, AttributeType>,
    IdentityAttributesCredentialsRandomness<C>,
)> {
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

    // Check that all the chosen identity providers (in the pre-identity object) are
    // available in the given context, and remove the ones that are not.
    let chosen_ars = {
        let mut chosen_ars = BTreeMap::new();
        for ar_id in prio.choice_ar_parameters.ar_identities.iter() {
            if let Some(info) = context.ars_infos.get(ar_id) {
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
    let (id_cred_data, cmm_id_cred_sec_sharing_coeff, cmm_coeff_randomness) =
        account_holder::compute_sharing_data(
            id_cred_sec,
            &chosen_ars,
            prio.choice_ar_parameters.threshold,
            &context.global_context.on_chain_commitment_key,
        );

    // filling ar data
    let ar_data = id_cred_data
        .iter()
        .map(|item| {
            (
                item.ar.ar_identity,
                ChainArData {
                    enc_id_cred_pub_share: item.encrypted_share,
                },
            )
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
        &cmm_id_cred_sec_sharing_coeff,
        cmm_coeff_randomness,
        &policy,
        &mut csprng,
    )?;

    // We have all the values now.
    let id_attribute_values = IdentityAttributesCredentialsValues {
        threshold: prio.choice_ar_parameters.threshold,
        ar_data,
        ip_identity: context.ip_info.ip_identity,
        policy,
    };

    // The label "IdentityAttributesCredentials" is appended to the transcript followed all
    // values of the identity attributes, specifically appending the
    // IdentityAttributesCommitmentValues struct.
    // This should make the proof non-reusable.
    // We should add the genesis hash also at some point
    transcript.append_label("IdentityAttributesCredentials");
    transcript.append_message("identity_attribute_values", &id_attribute_values);
    transcript.append_message("global_context", &context.global_context);

    // We now produce all the proofs.

    let mut id_cred_pub_share_numbers = Vec::with_capacity(id_cred_data.len());
    let mut id_cred_pub_provers = Vec::with_capacity(id_cred_data.len());
    let mut id_cred_pub_secrets = Vec::with_capacity(id_cred_data.len());

    // create provers for knowledge of id_cred_sec.
    for item in id_cred_data.iter() {
        let secret = com_enc_eq::ComEncEqSecret {
            value: item.share.clone(),
            elgamal_rand: item.encryption_randomness.clone(),
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

    let choice_ar_handles = id_attribute_values
        .ar_data
        .keys()
        .copied()
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
        first: prover_sig,
        second: ReplicateAdapter {
            protocols: id_cred_pub_provers,
        },
    };

    let secret = (secret_sig, id_cred_pub_secrets);
    let proof = match prove(transcript, &prover, secret, &mut csprng) {
        Some(x) => x,
        None => bail!("Cannot produce zero knowledge proof."),
    };

    let id_proofs = IdentityAttributesCredentialsProofs {
        sig: blinded_sig,
        commitments,
        challenge: proof.challenge,
        proof_id_cred_pub: id_cred_pub_share_numbers
            .into_iter()
            .zip(proof.response.r2.responses)
            .collect(),
        proof_ip_sig: proof.response.r1,
    };

    let info = IdentityAttributesCredentialsInfo {
        values: id_attribute_values,
        proofs: id_proofs,
    };

    let cmm_rand = IdentityAttributesCredentialsRandomness {
        attributes_rand: commitment_rands.attributes_rand,
    };

    Ok((info, cmm_rand))
}

#[allow(clippy::too_many_arguments)]
fn compute_pok_sig<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    commitment_key: &PedersenKey<C>,
    commitments: &IdentityAttributesCredentialsCommitments<C>,
    commitment_rands: &CommitmentRandomness<C>,
    id_cred_sec: &Value<C>,
    prf_key: &prf::SecretKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    threshold: Threshold,
    ar_list: &BTreeSet<ArIdentity>,
    ip_pub_key: &crate::ps_sig::PublicKey<P>,
    blinded_sig: &crate::ps_sig::BlindedSignature<P>,
    blind_rand: crate::ps_sig::BlindingRandomness<P>,
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
        ps_pub_key: ip_pub_key.clone(),
        comm_key: *commitment_key,
    };
    Ok((prover, secret))
}

/// Randomness for commitments
struct CommitmentRandomness<C: Curve> {
    /// Randomness of the commitment to idCredSec.
    id_cred_sec_rand: PedersenRandomness<C>,
    /// Randomness of the commitment to the PRF key.
    prf_rand: PedersenRandomness<C>,
    /// Randomness of the commitment to the maximum number of accounts the user
    /// may create from the identity object.
    max_accounts_rand: PedersenRandomness<C>,
    /// Randomness, if any, used to commit to user-chosen attributes, such as
    /// country of nationality.
    attributes_rand: BTreeMap<AttributeTag, PedersenRandomness<C>>,
}

/// Computing the commitments for the credential deployment info. We only
/// compute commitments for values that are not revealed as part of the policy.
/// For the other values the verifier (the chain) will compute commitments with
/// randomness 0 in order to verify knowledge of the signature.
fn compute_commitments<C: Curve, AttributeType: Attribute<C::Scalar>, R: Rng>(
    commitment_key: &PedersenKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    prf_key: &prf::SecretKey<C>,
    cmm_id_cred_sec_sharing_coeff: &[Commitment<C>],
    cmm_coeff_randomness: Vec<PedersenRandomness<C>>,
    policy: &Policy<C, AttributeType>,
    csprng: &mut R,
) -> anyhow::Result<(
    IdentityAttributesCredentialsCommitments<C>,
    CommitmentRandomness<C>,
)> {
    let id_cred_sec_rand = if let Some(v) = cmm_coeff_randomness.first() {
        v.clone()
    } else {
        bail!("Commitment randomness is an empty vector.");
    };

    let (cmm_prf, prf_rand) = commitment_key.commit(&prf_key, csprng);

    let max_accounts = Value::<C>::new(C::scalar_from_u64(u64::from(alist.max_accounts)));
    let (cmm_max_accounts, max_accounts_rand) = commitment_key.commit(&max_accounts, csprng);
    let att_vec = &alist.alist;
    let n = att_vec.len();
    // only commitments to attributes which are not revealed.
    ensure!(
        n >= policy.policy_vec.len(),
        "Attribute list is shorter than the number of revealed items in the policy."
    );
    let mut cmm_attributes = BTreeMap::new();
    let mut attributes_rand = BTreeMap::new();
    for (&i, val) in att_vec.iter() {
        // in case the value is openened there is no need to hide it.
        // We can just commit with randomness 0.
        if !policy.policy_vec.contains_key(&i) {
            let value = Value::<C>::new(val.to_field_element());
            let (cmm, attr_rand) = commitment_key.commit(&value, csprng);
            cmm_attributes.insert(i, cmm);
            attributes_rand.insert(i, attr_rand);
        }
    }
    let id_attr_cmms = IdentityAttributesCredentialsCommitments {
        cmm_prf,
        cmm_max_accounts,
        cmm_attributes,
        cmm_id_cred_sec_sharing_coeff: cmm_id_cred_sec_sharing_coeff.to_owned(),
    };

    let cmm_rand = CommitmentRandomness {
        id_cred_sec_rand,
        prf_rand,
        max_accounts_rand,
        attributes_rand,
    };
    Ok((id_attr_cmms, cmm_rand))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reason why verification of a credential commitment failed.
pub enum AttributeCommitmentVerificationError {
    IdCredPub,
    Signature,
    Ar,
    Proof,
}

impl Display for AttributeCommitmentVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AttributeCommitmentVerificationError::IdCredPub => {
                write!(f, "IdCredPubVerificationError")
            }
            AttributeCommitmentVerificationError::Signature => {
                write!(f, "SignatureVerificationError")
            }
            AttributeCommitmentVerificationError::Ar => {
                write!(f, "AnonymityRevokerVerificationError")
            }
            AttributeCommitmentVerificationError::Proof => write!(f, "ProofVerificationError"),
        }
    }
}
/// Verify attribute commitments created from identity credential.
pub fn verify_identity_attributes<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
    A: HasArPublicKey<C>,
>(
    global_context: &GlobalContext<C>,
    ip_info: &IpInfo<P>,
    // NB: The following map only needs to be a superset of the ars
    // in the identity attribute values.
    known_ars: &BTreeMap<ArIdentity, A>,
    id_attr_info: &IdentityAttributesCredentialsInfo<P, C, AttributeType>,
    transcript: &mut RandomOracle,
) -> Result<(), AttributeCommitmentVerificationError> {
    if ip_info.ip_identity != id_attr_info.values.ip_identity {
        return Err(AttributeCommitmentVerificationError::Signature);
    }
    // We need to check that the threshold is actually equal to
    // the number of coefficients in the sharing polynomial
    // (corresponding to the degree+1)
    let rt_usize: usize = id_attr_info.values.threshold.into();
    if rt_usize
        != id_attr_info
            .proofs
            .commitments
            .cmm_id_cred_sec_sharing_coeff
            .len()
    {
        return Err(AttributeCommitmentVerificationError::Ar);
    }
    let on_chain_commitment_key = global_context.on_chain_commitment_key;
    let ip_verify_key = &ip_info.ip_verify_key;
    // Compute the challenge prefix by hashing the values.
    transcript.append_label("IdentityAttributesCredentials");
    transcript.append_message("identity_attribute_values", &id_attr_info.values);
    transcript.append_message("global_context", &global_context);

    let commitments = &id_attr_info.proofs.commitments;

    let verifier_sig = pok_sig_verifier(
        &on_chain_commitment_key,
        id_attr_info.values.threshold,
        &id_attr_info
            .values
            .ar_data
            .keys()
            .copied()
            .collect::<BTreeSet<ArIdentity>>(),
        &id_attr_info.values.policy,
        commitments,
        ip_verify_key,
        &id_attr_info.proofs.sig,
    );
    let verifier_sig = if let Some(v) = verifier_sig {
        v
    } else {
        return Err(AttributeCommitmentVerificationError::Signature);
    };

    let response_sig = id_attr_info.proofs.proof_ip_sig.clone();

    let (id_cred_pub_verifier, id_cred_pub_responses) = id_cred_pub_verifier(
        &on_chain_commitment_key,
        known_ars,
        &id_attr_info.values.ar_data,
        &commitments.cmm_id_cred_sec_sharing_coeff,
        &id_attr_info.proofs.proof_id_cred_pub,
    )?;

    let verifier = AndAdapter {
        first: verifier_sig,
        second: id_cred_pub_verifier,
    };
    let response = AndResponse {
        r1: response_sig,
        r2: id_cred_pub_responses,
    };
    let proof = SigmaProof {
        challenge: id_attr_info.proofs.challenge,
        response,
    };

    if !verify(transcript, &verifier, &proof) {
        return Err(AttributeCommitmentVerificationError::Proof);
    }

    Ok(())
}

/// verify id_cred data
fn id_cred_pub_verifier<C: Curve, A: HasArPublicKey<C>>(
    commitment_key: &CommitmentKey<C>,
    known_ars: &BTreeMap<ArIdentity, A>,
    chain_ar_data: &BTreeMap<ArIdentity, ChainArData<C>>,
    cmm_sharing_coeff: &[Commitment<C>],
    proof_id_cred_pub: &BTreeMap<ArIdentity, com_enc_eq::Response<C>>,
) -> Result<IdCredPubVerifiers<C>, AttributeCommitmentVerificationError> {
    let mut provers = Vec::with_capacity(proof_id_cred_pub.len());
    let mut responses = Vec::with_capacity(proof_id_cred_pub.len());

    // The encryptions and the proofs have to match.
    if chain_ar_data.len() != proof_id_cred_pub.len() {
        return Err(AttributeCommitmentVerificationError::IdCredPub);
    }

    // The following relies on the fact that iterators over BTreeMap are
    // over sorted values.
    for ((ar_id, ar_data), (ar_id_1, response)) in
        chain_ar_data.iter().zip(proof_id_cred_pub.iter())
    {
        if ar_id != ar_id_1 {
            return Err(AttributeCommitmentVerificationError::IdCredPub);
        }
        let cmm_share = utils::commitment_to_share(&ar_id.to_scalar::<C>(), cmm_sharing_coeff);

        // finding the correct AR data.
        let ar_info = known_ars
            .get(ar_id)
            .ok_or(AttributeCommitmentVerificationError::IdCredPub)?;
        let item_prover = com_enc_eq::ComEncEq {
            cipher: ar_data.enc_id_cred_pub_share,
            commitment: cmm_share,
            pub_key: *ar_info.get_public_key(),
            cmm_key: *commitment_key,
            encryption_in_exponent_generator: ar_info.get_public_key().generator,
        };
        provers.push(item_prover);
        responses.push(response.clone());
    }
    Ok((
        ReplicateAdapter { protocols: provers },
        ReplicateResponse { responses },
    ))
}

/// Verify the proof of knowledge of signature on the attribute list.
/// A none return value means we cannot construct a verifier, and consequently
/// it should be interpreted as the signature being invalid.
fn pok_sig_verifier<
    'a,
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    commitment_key: &'a CommitmentKey<C>,
    threshold: Threshold,
    choice_ar_parameters: &BTreeSet<ArIdentity>,
    policy: &'a Policy<C, AttributeType>,
    commitments: &'a IdentityAttributesCredentialsCommitments<C>,
    ip_pub_key: &'a crate::ps_sig::PublicKey<P>,
    blinded_sig: &'a crate::ps_sig::BlindedSignature<P>,
) -> Option<com_eq_sig::ComEqSig<P, C>> {
    let ar_scalars = utils::encode_ars(choice_ar_parameters)?;
    // Capacity for id_cred_sec, cmm_prf, (threshold, valid_to, created_at), tags
    // ar_scalars and cmm_attributes
    let mut comm_vec = Vec::with_capacity(4 + ar_scalars.len() + commitments.cmm_attributes.len());
    let cmm_id_cred_sec = *commitments.cmm_id_cred_sec_sharing_coeff.first()?;
    comm_vec.push(cmm_id_cred_sec);
    comm_vec.push(commitments.cmm_prf);

    // compute commitments with randomness 0
    let zero = Randomness::zero();
    let public_params =
        utils::encode_public_credential_values(policy.created_at, policy.valid_to, threshold)
            .ok()?;
    // add commitment to public values with randomness 0
    comm_vec.push(commitment_key.hide_worker(&public_params, &zero));
    // and all commitments to ARs with randomness 0
    for ar in ar_scalars {
        comm_vec.push(commitment_key.hide_worker(&ar, &zero));
    }

    let tags = {
        match utils::encode_tags::<C::Scalar, _>(
            policy
                .policy_vec
                .keys()
                .chain(commitments.cmm_attributes.keys()),
        ) {
            Ok(v) => v,
            Err(_) => return None,
        }
    };

    // add commitment with randomness 0 for variant, valid_to and created_at
    comm_vec.push(commitment_key.hide(&Value::<C>::new(tags), &zero));
    comm_vec.push(commitments.cmm_max_accounts);

    // now, we go through the policy and remaining commitments and
    // put them into the vector of commitments in order to check the signature.
    // NB: It is crucial that they are put into the vector ordered by tags, since
    // otherwise the signature will not check out.
    // At this point we know all tags are distinct.

    let f = |v: Either<&AttributeType, &Commitment<_>>| match v {
        Either::Left(v) => {
            let value = Value::<C>::new(v.to_field_element());
            comm_vec.push(commitment_key.hide(&value, &zero));
        }
        Either::Right(v) => {
            comm_vec.push(*v);
        }
    };

    utils::merge_iter(
        policy.policy_vec.iter(),
        commitments.cmm_attributes.iter(),
        f,
    );

    Some(com_eq_sig::ComEqSig {
        blinded_sig: blinded_sig.clone(),
        commitments: comm_vec,
        ps_pub_key: ip_pub_key.clone(),
        comm_key: *commitment_key,
    })
}

#[cfg(test)]
mod test {
    use crate::curve_arithmetic::Curve;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::identity_attributes_credentials::{
        prove_identity_attributes, verify_identity_attributes, AttributeCommitmentVerificationError,
    };
    use crate::id::types::{
        ArIdentity, ArInfo, GlobalContext, IdObjectUseData, IdentityObjectV1, IpContext, IpData,
        IpInfo, Policy,
    };
    use crate::id::{identity_provider, test};
    use crate::random_oracle::RandomOracle;
    use assert_matches::assert_matches;
    use std::collections::BTreeMap;

    struct IdentityObjectFixture {
        id_object: IdentityObjectV1<IpPairing, ArCurve, AttributeKind>,
        id_use_data: IdObjectUseData<IpPairing, ArCurve>,
        ip_info: IpInfo<IpPairing>,
        ars_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
        global_ctx: GlobalContext<ArCurve>,
    }

    /// Create identity object for use in tests
    fn identity_object_fixture() -> IdentityObjectFixture {
        let mut csprng = rand::thread_rng();

        let max_attrs = 10;
        let num_ars = 5;
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ..
        } = test::test_create_ip_info(&mut csprng, num_ars, max_attrs);

        let global_ctx = GlobalContext::generate(String::from("genesis_string"));

        let (ars_infos, _ars_secret) =
            test::test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);

        let id_use_data = test::test_create_id_use_data(&mut csprng);
        let (context, pio, _randomness) =
            test::test_create_pio_v1(&id_use_data, &ip_info, &ars_infos, &global_ctx, num_ars);
        let alist = test::test_create_attributes();
        let ip_sig =
            identity_provider::verify_credentials_v1(&pio, context, &alist, &ip_secret_key)
                .expect("verify credentials");

        let id_object = IdentityObjectV1 {
            pre_identity_object: pio,
            alist: alist.clone(),
            signature: ip_sig,
        };

        IdentityObjectFixture {
            id_object,
            id_use_data,
            ars_infos,
            ip_info,
            global_ctx,
        }
    }

    fn ip_context(id_object_fixture: &IdentityObjectFixture) -> IpContext<'_, IpPairing, ArCurve> {
        IpContext {
            ip_info: &id_object_fixture.ip_info,
            ars_infos: &id_object_fixture.ars_infos,
            global_context: &id_object_fixture.global_ctx,
        }
    }

    /// Test that the verifier accepts a valid proof
    #[test]
    pub fn test_identity_attributes_completeness() {
        let id_object_fixture = identity_object_fixture();

        let policy = Policy {
            valid_to: id_object_fixture.id_object.alist.valid_to,
            created_at: id_object_fixture.id_object.alist.created_at,
            policy_vec: Default::default(),
            _phantom: Default::default(),
        };

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            policy,
            &mut transcript,
        )
        .expect("prove");

        let mut transcript = RandomOracle::empty();
        verify_identity_attributes(
            &id_object_fixture.global_ctx,
            &id_object_fixture.ip_info,
            &id_object_fixture.ars_infos,
            &id_attr_info,
            &mut transcript,
        )
        .expect("verify");
    }

    /// Test that the verifier accepts a valid proof. Test variant with revealed attribute values
    #[test]
    pub fn test_identity_attributes_completeness_with_revealed_attributes() {
        let id_object_fixture = identity_object_fixture();
        let reveal = id_object_fixture
            .id_object
            .alist
            .alist
            .first_key_value()
            .unwrap();

        let policy = Policy {
            valid_to: id_object_fixture.id_object.alist.valid_to,
            created_at: id_object_fixture.id_object.alist.created_at,
            policy_vec: [(*reveal.0, reveal.1.clone())].into_iter().collect(),
            _phantom: Default::default(),
        };

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            policy,
            &mut transcript,
        )
        .expect("prove");

        let mut transcript = RandomOracle::empty();
        verify_identity_attributes(
            &id_object_fixture.global_ctx,
            &id_object_fixture.ip_info,
            &id_object_fixture.ars_infos,
            &id_attr_info,
            &mut transcript,
        )
        .expect("verify");
    }

    /// Test that the verifier does not accept the proof if the
    /// id cred pub encryption
    #[test]
    pub fn test_identity_attributes_soundness_ar_shares_encryption() {
        let id_object_fixture = identity_object_fixture();

        let policy = Policy {
            valid_to: id_object_fixture.id_object.alist.valid_to,
            created_at: id_object_fixture.id_object.alist.created_at,
            policy_vec: Default::default(),
            _phantom: Default::default(),
        };

        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            policy,
            &mut transcript,
        )
        .expect("prove");

        // make one of the ar share encryptions invalid
        let enc = id_attr_info.values.ar_data.values_mut().next().unwrap();
        enc.enc_id_cred_pub_share.1 = enc
            .enc_id_cred_pub_share
            .1
            .plus_point(&ArCurve::one_point());

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            &id_object_fixture.ip_info,
            &id_object_fixture.ars_infos,
            &id_attr_info,
            &mut transcript,
        );

        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that the verifier fails if identity provider is not set correctly.
    #[test]
    pub fn test_identity_attributes_soundness_ip() {
        let id_object_fixture = identity_object_fixture();

        let policy = Policy {
            valid_to: id_object_fixture.id_object.alist.valid_to,
            created_at: id_object_fixture.id_object.alist.created_at,
            policy_vec: Default::default(),
            _phantom: Default::default(),
        };

        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            policy,
            &mut transcript,
        )
        .expect("prove");

        id_attr_info.values.ip_identity.0 += 1;

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            &id_object_fixture.ip_info,
            &id_object_fixture.ars_infos,
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Signature));
    }

    /// Test that the verifier does not accept the proof if the
    /// identity provider signature does not match the provided values.
    #[test]
    pub fn test_identity_attributes_soundness_ip_signature() {
        let id_object_fixture = identity_object_fixture();

        let policy = Policy {
            valid_to: id_object_fixture.id_object.alist.valid_to,
            created_at: id_object_fixture.id_object.alist.created_at,
            policy_vec: Default::default(),
            _phantom: Default::default(),
        };

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            policy,
            &mut transcript,
        )
        .expect("prove");

        // change one of the public values in the signature: decrease ar threshold
        let mut id_attr_info_invalid = id_attr_info.clone();
        id_attr_info_invalid.values.threshold.0 -= 1;
        id_attr_info_invalid
            .proofs
            .commitments
            .cmm_id_cred_sec_sharing_coeff
            .pop();

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            &id_object_fixture.ip_info,
            &id_object_fixture.ars_infos,
            &id_attr_info_invalid,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));

        // change one of the public values in the signature: remove one of the ars
        let mut id_attr_info_invalid = id_attr_info.clone();
        let ar_to_remove = *id_attr_info_invalid.values.ar_data.keys().next().unwrap();
        id_attr_info_invalid.values.ar_data.remove(&ar_to_remove);
        id_attr_info_invalid
            .proofs
            .proof_id_cred_pub
            .remove(&ar_to_remove);

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            &id_object_fixture.ip_info,
            &id_object_fixture.ars_infos,
            &id_attr_info_invalid,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));

        // change one of the committed values in the signature
        let mut id_attr_info_invalid = id_attr_info.clone();
        let attr_cmm = id_attr_info_invalid
            .proofs
            .commitments
            .cmm_attributes
            .values_mut()
            .next()
            .unwrap();
        attr_cmm.0 = attr_cmm.0.plus_point(&ArCurve::one_point());

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            &id_object_fixture.ip_info,
            &id_object_fixture.ars_infos,
            &id_attr_info_invalid,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }
}
