//! Functionality to prove and verify identity attribute credentials based on identity credentials. These are to a large
//! extent equivalent to account credentials deployed on chain, but there is no on-chain account credentials involved.

use super::{account_holder, types::*, utils};
use crate::pedersen_commitment::{CommitmentKey, Randomness};
use crate::sigma_protocols::ps_sig_known::{PsSigKnown, PsSigMsg, PsSigWitness, PsSigWitnessMsg};
use crate::{
    curve_arithmetic::{Curve, Pairing},
    pedersen_commitment::{
        Commitment, CommitmentKey as PedersenKey, Randomness as PedersenRandomness, Value,
    },
    ps_sig,
    random_oracle::RandomOracle,
    sigma_protocols::{com_enc_eq, common::*},
};
use anyhow::Context;
use core::fmt;
use core::fmt::Display;
use rand::*;
use std::collections::{btree_map::BTreeMap, BTreeSet};

/// How to handle an identity credential attribute
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum IdentityAttributeHandling {
    /// The attribute value should be committed to (value will be verified by the proof)
    Commit,
    /// The attribute value should be Public (value will be verified by the proof)
    Reveal,
}

/// Construct proof for attribute credentials from identity credential. The map `attributes_handling`
/// specifies how to handle attributes in the identity credentials `id_object`. If not specified,
/// the attribute is just proven known.
pub fn prove_identity_attributes<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Clone + Attribute<C::Scalar>,
>(
    context: IpContext<'_, P, C>,
    id_object: &impl HasIdentityObjectFields<P, C, AttributeType>,
    id_object_use_data: &IdObjectUseData<P, C>,
    attributes_handling: &BTreeMap<AttributeTag, IdentityAttributeHandling>,
    transcript: &mut RandomOracle,
) -> anyhow::Result<(
    IdentityAttributesCredentialsInfo<P, C, AttributeType>,
    IdentityAttributesCredentialsRandomness<C>,
)> {
    let mut csprng = thread_rng();

    // Lookup keys for the anonymity revokers
    let ars = {
        let mut ars = BTreeMap::new();
        for ar_id in id_object
            .get_common_pio_fields()
            .choice_ar_parameters
            .ar_identities
            .iter()
        {
            let info = context.ars_infos.get(ar_id).with_context(|| {
                format!("cannot find anonymity revoker {} in the context", ar_id)
            })?;
            ars.insert(*ar_id, info.clone());
        }
        ars
    };

    // Compute sharing data for id cred sec
    let (id_cred_data, cmm_id_cred_sec_sharing_coeff, cmm_rand_id_cred_sec_sharing_coeff) =
        account_holder::compute_sharing_data(
            &id_object_use_data.aci.cred_holder_info.id_cred.id_cred_sec,
            &ars,
            id_object
                .get_common_pio_fields()
                .choice_ar_parameters
                .threshold,
            &context.global_context.on_chain_commitment_key,
        );

    // Create ar data map
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

    let mut id_cred_pub_share_numbers = Vec::with_capacity(id_cred_data.len());
    let mut id_cred_pub_provers = Vec::with_capacity(id_cred_data.len());
    let mut id_cred_pub_secrets = Vec::with_capacity(id_cred_data.len());

    // Create provers for correct encryption of IdCredSec
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

    let cmm_id_cred_sec = *cmm_id_cred_sec_sharing_coeff
        .get(0)
        .context("id cred sharing commitment")?;
    let cmm_rand_id_cred_sec = cmm_rand_id_cred_sec_sharing_coeff
        .get(0)
        .context("id cred sharing commitment randomness")?
        .clone();

    // Proof of knowledge of the signature of the identity provider.
    let (prover_sig, secret_sig, sig_pok_output) = compute_pok_sig(
        &mut csprng,
        &context.global_context.on_chain_commitment_key,
        &context.ip_info.ip_verify_key,
        id_object,
        id_object_use_data,
        attributes_handling,
        cmm_id_cred_sec,
        cmm_rand_id_cred_sec,
    )?;

    let prover = AndAdapter {
        first: prover_sig,
        second: ReplicateAdapter {
            protocols: id_cred_pub_provers,
        },
    };

    let secret = (secret_sig, id_cred_pub_secrets);

    let validity = CredentialValidity {
        valid_to: id_object.get_attribute_list().valid_to,
        created_at: id_object.get_attribute_list().created_at,
    };

    let commitments = IdentityAttributesCredentialsCommitments {
        cmm_id_cred_sec_sharing_coeff: cmm_id_cred_sec_sharing_coeff.to_owned(),
    };

    let cmm_rand = IdentityAttributesCredentialsRandomness {
        attributes_rand: sig_pok_output.attribute_cmm_rand,
    };

    let id_attribute_values = IdentityAttributesCredentialsValues {
        threshold: id_object
            .get_common_pio_fields()
            .choice_ar_parameters
            .threshold,
        ar_data,
        ip_identity: context.ip_info.ip_identity,
        validity,
        attributes: sig_pok_output.attributes,
    };

    // The label "IdentityAttributesCredentials" is appended to the transcript followed all
    // values of the identity attributes, specifically appending the
    // IdentityAttributesCommitmentValues struct.
    // This should make the proof non-reusable.
    // We should add the genesis hash also at some point
    transcript.add_bytes(b"IdentityAttributesCredentials");
    transcript.append_message(b"identity_attribute_values", &id_attribute_values);
    transcript.append_message(b"global_context", &context.global_context);

    let proof = prove(transcript, &prover, secret, &mut csprng)
        .context("cannot produce zero knowledge proof")?;

    let id_proofs = IdentityAttributesCredentialsProofs {
        sig: sig_pok_output.blinded_sig,
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

    Ok((info, cmm_rand))
}

/// Data we need output as side effect from the signature proof of knowledge
struct SignaturePokOutput<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    attributes: BTreeMap<AttributeTag, IdentityAttribute<C, AttributeType>>,
    attribute_cmm_rand: BTreeMap<AttributeTag, PedersenRandomness<C>>,
    blinded_sig: ps_sig::BlindedSignature<P>,
}

fn compute_pok_sig<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    csprng: &mut impl Rng,
    commitment_key: &PedersenKey<C>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    id_object: &impl HasIdentityObjectFields<P, C, AttributeType>,
    id_object_use_data: &IdObjectUseData<P, C>,
    attributes_handling: &BTreeMap<AttributeTag, IdentityAttributeHandling>,
    cmm_id_cred_sec: Commitment<C>,
    cmm_rand_id_cred_sec: Randomness<C>,
) -> anyhow::Result<(
    PsSigKnown<P, C>,
    PsSigWitness<P, C>,
    SignaturePokOutput<P, C, AttributeType>,
)> {
    // The identity provider signature is on a message of:
    // - idcredsec (signed blindly)
    // - prf key (signed blindly)
    // - created_at, valid_to dates of the attribute list and revocation threshold
    // - encoding of anonymity revoker ids
    // - tags of the attribute list
    // - max accounts
    // - attribute values

    let ar_scalars = utils::encode_ars(
        &id_object
            .get_common_pio_fields()
            .choice_ar_parameters
            .ar_identities,
    )
    .context("cannot encode anonymity revokers")?;

    let alist = id_object.get_attribute_list();
    let msg_count = alist.alist.len() + ar_scalars.len() + 5;

    let mut msgs = Vec::with_capacity(msg_count);
    let mut secrets = Vec::with_capacity(msg_count);

    // For IdCredSec, we prove equal to a commitment in order to link the signature proof
    // to the IdCredSec encryption parts proofs
    msgs.push(PsSigMsg::EqualToCommitment(cmm_id_cred_sec));
    secrets.push(PsSigWitnessMsg::EqualToCommitment(
        id_object_use_data
            .aci
            .cred_holder_info
            .id_cred
            .id_cred_sec
            .clone(),
        cmm_rand_id_cred_sec,
    ));

    // The PRF secret key we just prove knowledge of
    msgs.push(PsSigMsg::Known);
    secrets.push(PsSigWitnessMsg::Known(
        id_object_use_data.aci.prf_key.to_value(),
    ));

    // Validity and threshold are "public" values
    let public_vals = utils::encode_public_credential_values(
        alist.created_at,
        alist.valid_to,
        id_object
            .get_common_pio_fields()
            .choice_ar_parameters
            .threshold,
    )?;
    msgs.push(PsSigMsg::Public(Value::new(public_vals)));
    secrets.push(PsSigWitnessMsg::Public);

    // Anonymity revoker ids are public values
    for ar_scalar in ar_scalars {
        msgs.push(PsSigMsg::Public(Value::new(ar_scalar)));
        secrets.push(PsSigWitnessMsg::Public);
    }

    // Attribute tag set is a public value
    let tags_val = utils::encode_tags(alist.alist.keys())?;
    msgs.push(PsSigMsg::Public(Value::new(tags_val)));
    secrets.push(PsSigWitnessMsg::Public);

    // Max accounts is not public, we prove knowledge of it
    let max_accounts_val = C::scalar_from_u64(alist.max_accounts.into());
    msgs.push(PsSigMsg::Known);
    secrets.push(PsSigWitnessMsg::Known(Value::new(max_accounts_val)));

    let mut attributes = BTreeMap::new();
    let mut attribute_rand = BTreeMap::new();
    // Iterate attributes in the same order as signed by the identity provider (tag order)
    for (tag, attribute) in &alist.alist {
        let value = Value::<C>::new(attribute.to_field_element());
        match attributes_handling.get(tag) {
            Some(IdentityAttributeHandling::Commit) => {
                let (attr_cmm, attr_rand) = commitment_key.commit(&value, csprng);
                msgs.push(PsSigMsg::EqualToCommitment(attr_cmm));
                secrets.push(PsSigWitnessMsg::EqualToCommitment(value, attr_rand.clone()));
                attributes.insert(*tag, IdentityAttribute::Committed(attr_cmm));
                attribute_rand.insert(*tag, attr_rand);
            }
            Some(IdentityAttributeHandling::Reveal) => {
                msgs.push(PsSigMsg::Public(value));
                secrets.push(PsSigWitnessMsg::Public);
                attributes.insert(*tag, IdentityAttribute::Revealed(Clone::clone(attribute)));
            }
            None => {
                msgs.push(PsSigMsg::Known);
                secrets.push(PsSigWitnessMsg::Known(value));
                attributes.insert(*tag, IdentityAttribute::Known);
            }
        }
    }

    // Prepare a fresh blinded signature for the proof.
    // retrieve the signature on the underlying idcredsec + prf_key + attribute_list
    let retrieved_sig = id_object
        .get_signature()
        .retrieve(&id_object_use_data.randomness);
    // and then we blind the signature to disassociate it from the message.
    // only the second part is used (as per the protocol)
    let (blinded_sig, blind_rand) = retrieved_sig.blind(csprng);

    let secret = PsSigWitness {
        r_prime: blind_rand.1,
        msgs: secrets,
    };
    let prover = PsSigKnown {
        blinded_sig: blinded_sig.clone(),
        msgs,
        ps_pub_key: ip_pub_key.clone(),
        cmm_key: *commitment_key,
    };

    let output = SignaturePokOutput {
        attributes,
        attribute_cmm_rand: attribute_rand,
        blinded_sig,
    };

    Ok((prover, secret, output))
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

    // Compute the challenge prefix by hashing the values.
    transcript.add_bytes(b"IdentityAttributesCredentials");
    transcript.append_message(b"identity_attribute_values", &id_attr_info.values);
    transcript.append_message(b"global_context", &global_context);

    let commitments = &id_attr_info.proofs.commitments;

    let verifier_sig = pok_sig_verifier(
        &global_context.on_chain_commitment_key,
        &ip_info.ip_verify_key,
        id_attr_info,
    )
    .ok_or(AttributeCommitmentVerificationError::Signature)?;

    let (id_cred_pub_verifier, id_cred_pub_responses) = id_cred_pub_verifier(
        &global_context.on_chain_commitment_key,
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
        r1: id_attr_info.proofs.proof_ip_sig.clone(),
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
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    commitment_key: &CommitmentKey<C>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    id_attr_info: &IdentityAttributesCredentialsInfo<P, C, AttributeType>,
) -> Option<PsSigKnown<P, C>> {
    // The identity provider signature is on a message of:
    // - idcredsec (signed blindly)
    // - prf key (signed blindly)
    // - created_at, valid_to dates of the attribute list and revocation threshold
    // - encoding of anonymity revoker ids
    // - tags of the attribute list
    // - max accounts
    // - attribute values

    let ar_scalars = utils::encode_ars(
        &id_attr_info
            .values
            .ar_data
            .keys()
            .copied()
            .collect::<BTreeSet<ArIdentity>>(),
    )?;

    let msg_count = id_attr_info.values.attributes.len() + ar_scalars.len() + 5;

    let mut msgs = Vec::with_capacity(msg_count);

    // For IdCredSec, we verify equal to a commitment in order to link the signature proof
    // to the IdCredSec encryption parts proofs
    msgs.push(PsSigMsg::EqualToCommitment(
        *id_attr_info
            .proofs
            .commitments
            .cmm_id_cred_sec_sharing_coeff
            .get(0)?,
    ));

    // The PRF secret key we just verify knowledge of
    msgs.push(PsSigMsg::Known);

    // Validity and threshold are "public" values
    let public_vals = utils::encode_public_credential_values(
        id_attr_info.values.validity.created_at,
        id_attr_info.values.validity.valid_to,
        id_attr_info.values.threshold,
    )
    .ok()?;
    msgs.push(PsSigMsg::Public(Value::new(public_vals)));

    // Anonymity revoker ids are public values
    for ar_scalar in ar_scalars {
        msgs.push(PsSigMsg::Public(Value::new(ar_scalar)));
    }

    // Attribute tag set is a public value
    let tags_val = utils::encode_tags(id_attr_info.values.attributes.keys()).ok()?;
    msgs.push(PsSigMsg::Public(Value::new(tags_val)));

    // Max accounts is not public, we verify knowledge of it
    msgs.push(PsSigMsg::Known);

    // Iterate attributes in the same order as signed by the identity provider (tag order)
    for (_tag, attribute) in &id_attr_info.values.attributes {
        match attribute {
            IdentityAttribute::Committed(attr_cmm) => {
                msgs.push(PsSigMsg::EqualToCommitment(*attr_cmm));
            }
            IdentityAttribute::Revealed(value) => {
                msgs.push(PsSigMsg::Public(Value::new(value.to_field_element())));
            }
            IdentityAttribute::Known => {
                msgs.push(PsSigMsg::Known);
            }
        }
    }

    Some(PsSigKnown {
        blinded_sig: id_attr_info.proofs.sig.clone(),
        msgs,
        ps_pub_key: ip_pub_key.clone(),
        cmm_key: *commitment_key,
    })
}

#[cfg(test)]
mod test {
    use crate::curve_arithmetic::Curve;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::identity_attributes_credentials::{
        prove_identity_attributes, verify_identity_attributes,
        AttributeCommitmentVerificationError, IdentityAttributeHandling,
    };
    use crate::id::test::ExampleAttributeList;
    use crate::id::types::{
        ArIdentity, ArInfo, AttributeTag, GlobalContext, IdObjectUseData, IdentityObjectV1,
        IpContext, IpData, IpInfo, YearMonth,
    };
    use crate::id::{identity_provider, test};
    use crate::random_oracle::RandomOracle;
    use assert_matches::assert_matches;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    struct IdentityObjectFixture {
        id_object: IdentityObjectV1<IpPairing, ArCurve, AttributeKind>,
        id_use_data: IdObjectUseData<IpPairing, ArCurve>,
        ip_info: IpInfo<IpPairing>,
        ars_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
        global_ctx: GlobalContext<ArCurve>,
    }

    fn test_create_attributes() -> ExampleAttributeList {
        let mut alist = BTreeMap::new();
        alist.insert(AttributeTag::from(0u8), AttributeKind::from(55));
        alist.insert(
            AttributeTag::from(3u8),
            AttributeKind::from_str("test1").unwrap(),
        );
        alist.insert(AttributeTag::from(8u8), AttributeKind::from(31));

        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
        ExampleAttributeList {
            valid_to,
            created_at,
            max_accounts: 237,
            alist,
            _phantom: Default::default(),
        }
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
        let alist = test_create_attributes();
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

    // todo ar tests

    // todo ar test specify handling of attributes not in credentials

    /// Test that the verifier accepts a valid proof
    #[test]
    pub fn test_identity_attributes_completeness_commit() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = id_object_fixture
            .id_object
            .alist
            .alist
            .keys()
            .copied()
            .map(|tag| (tag, IdentityAttributeHandling::Commit))
            .collect();

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
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

    /// Test that the verifier accepts a valid proof
    #[test]
    pub fn test_identity_attributes_completeness_reveal() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = id_object_fixture
            .id_object
            .alist
            .alist
            .keys()
            .copied()
            .map(|tag| (tag, IdentityAttributeHandling::Reveal))
            .collect();

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
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

    /// Test that the verifier accepts a valid proof
    #[test]
    pub fn test_identity_attributes_completeness_known() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = id_object_fixture
            .id_object
            .alist
            .alist
            .keys()
            .copied()
            .map(|tag| (tag, IdentityAttributeHandling::Reveal))
            .collect();

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
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

        let attributes_handling = id_object_fixture
            .id_object
            .alist
            .alist
            .keys()
            .copied()
            .map(|tag| (tag, IdentityAttributeHandling::Commit))
            .collect();

        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
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

        let attributes_handling = id_object_fixture
            .id_object
            .alist
            .alist
            .keys()
            .copied()
            .map(|tag| (tag, IdentityAttributeHandling::Commit))
            .collect();

        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
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

        let attributes_handling = id_object_fixture
            .id_object
            .alist
            .alist
            .keys()
            .copied()
            .map(|tag| (tag, IdentityAttributeHandling::Commit))
            .collect();

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
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

        // todo ar
        // // change one of the committed values in the signature
        // let mut id_attr_info_invalid = id_attr_info.clone();
        // let attr_cmm = id_attr_info_invalid
        //     .proofs
        //     .commitments
        //     .cmm_attributes
        //     .values_mut()
        //     .next()
        //     .unwrap();
        // attr_cmm.0 = attr_cmm.0.plus_point(&ArCurve::one_point());
        //
        // let mut transcript = RandomOracle::empty();
        // let res = verify_identity_attributes(
        //     &id_object_fixture.global_ctx,
        //     &id_object_fixture.ip_info,
        //     &id_object_fixture.ars_infos,
        //     &id_attr_info_invalid,
        //     &mut transcript,
        // );
        // assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }
}
