//! Functionality to prove and verify identity attribute credentials based on identity credentials. These are to a large
//! extent equivalent to account credentials deployed on chain, but there is no on-chain account credentials involved.

use super::{account_holder, types::*, utils};
use crate::pedersen_commitment::{CommitmentKey, Randomness};
use crate::random_oracle::StructuredDigest;
use crate::sigma_protocols::common::{
    AndAdapter, AndResponse, ReplicateAdapter, ReplicateResponse, SigmaProof,
};
use crate::sigma_protocols::ps_sig_known::{PsSigKnown, PsSigMsg, PsSigWitness, PsSigWitnessMsg};
use crate::{
    curve_arithmetic::{Curve, Pairing},
    pedersen_commitment::{
        Commitment, CommitmentKey as PedersenKey, Randomness as PedersenRandomness, Value,
    },
    ps_sig,
    random_oracle::RandomOracle,
    sigma_protocols,
    sigma_protocols::com_enc_eq,
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
    global_context: &GlobalContext<C>,
    ip_context: IpContextOnly<'_, P, C>,
    id_object: &(impl HasIdentityObjectFields<P, C, AttributeType> + ?Sized),
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
            let info = ip_context.ars_infos.get(ar_id).with_context(|| {
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
            &global_context.on_chain_commitment_key,
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
    let mut id_cred_pub_witnesses = Vec::with_capacity(id_cred_data.len());

    // Create provers for correct encryption of IdCredSec
    for item in id_cred_data.iter() {
        let witness = com_enc_eq::ComEncEqSecret {
            value: item.share.clone(),
            elgamal_rand: item.encryption_randomness.clone(),
            pedersen_rand: item.randomness_cmm_to_share.clone(),
        };

        let item_prover = com_enc_eq::ComEncEq {
            cipher: item.encrypted_share,
            commitment: item.cmm_to_share,
            pub_key: item.ar.ar_public_key,
            cmm_key: global_context.on_chain_commitment_key,
            encryption_in_exponent_generator: item.ar.ar_public_key.generator,
        };

        id_cred_pub_share_numbers.push(item.ar.ar_identity);
        id_cred_pub_provers.push(item_prover);
        id_cred_pub_witnesses.push(witness);
    }

    let cmm_id_cred_sec = *cmm_id_cred_sec_sharing_coeff
        .first()
        .context("id cred sharing commitment")?;
    let cmm_rand_id_cred_sec = cmm_rand_id_cred_sec_sharing_coeff
        .first()
        .context("id cred sharing commitment randomness")?
        .clone();

    // Proof of knowledge of the signature of the identity provider.
    let (prover_signature, witness_signature, signature_pok_output) = signature_knowledge_prover(
        &mut csprng,
        &global_context.on_chain_commitment_key,
        &ip_context.ip_info.ip_verify_key,
        id_object,
        id_object_use_data,
        attributes_handling,
        cmm_id_cred_sec,
        cmm_rand_id_cred_sec,
    )?;

    // We "and" the signature proof of knowledge and the IdCredSec share encryption provers.
    // The commitment to the coefficients of the sharing polynomial bind the generated proofs together
    // such that we actually prove that the signed IdCredSec is what is encrypted in the shares.
    let prover = AndAdapter {
        first: prover_signature,
        second: ReplicateAdapter {
            protocols: id_cred_pub_provers,
        },
    };

    let witness = (witness_signature, id_cred_pub_witnesses);

    let validity = CredentialValidity {
        valid_to: id_object.get_attribute_list().valid_to,
        created_at: id_object.get_attribute_list().created_at,
    };

    let commitments = IdentityAttributesCredentialsCommitments {
        cmm_id_cred_sec_sharing_coeff: cmm_id_cred_sec_sharing_coeff.to_owned(),
    };

    let cmm_rand = IdentityAttributesCredentialsRandomness {
        attributes_rand: signature_pok_output.attribute_cmm_rand,
    };

    let id_attribute_values = IdentityAttributesCredentialsValues {
        threshold: id_object
            .get_common_pio_fields()
            .choice_ar_parameters
            .threshold,
        ar_data,
        ip_identity: ip_context.ip_info.ip_identity,
        validity,
        attributes: signature_pok_output.attributes,
    };

    // The label "IdentityAttributesCredentials" is appended to the transcript followed all
    // values of the identity attribute credentials, specifically appending the
    // IdentityAttributesCommitmentValues struct.
    // This should make the proof non-reusable.
    // We should add the genesis hash also at some point
    transcript.add_bytes(b"IdentityAttributesCredentials");
    transcript.append_message(b"identity_attribute_values", &id_attribute_values);
    transcript.append_message(b"global_context", &global_context);

    let proof = sigma_protocols::common::prove(transcript, &prover, witness, &mut csprng)
        .context("cannot produce zero knowledge proof")?;

    let id_proofs = IdentityAttributesCredentialsProofs {
        signature: signature_pok_output.blinded_sig,
        commitments,
        challenge: proof.challenge,
        proof_id_cred_pub: id_cred_pub_share_numbers
            .into_iter()
            .zip(proof.response.r2.responses)
            .collect(),
        proof_ip_signature: proof.response.r1,
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
    /// Representation of each attribute in the attribute credentials
    attributes: BTreeMap<AttributeTag, IdentityAttribute<C, AttributeType>>,
    /// Commitment randomness for the attributes we commit to
    attribute_cmm_rand: BTreeMap<AttributeTag, PedersenRandomness<C>>,
    /// Signature with fresh blinding randomness
    blinded_sig: ps_sig::BlindedSignature<P>,
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn signature_knowledge_prover<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    csprng: &mut impl Rng,
    commitment_key: &PedersenKey<C>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    id_object: &(impl HasIdentityObjectFields<P, C, AttributeType> + ?Sized),
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

    // Attribute tag set we choose not to be public. In that way we only disclose the tags
    // for the attributes we commit to or reveal.
    let tags_val = utils::encode_tags(alist.alist.keys())?;
    msgs.push(PsSigMsg::Known);
    secrets.push(PsSigWitnessMsg::Known(Value::new(tags_val)));

    // Max accounts is not public, we prove knowledge of it
    let max_accounts_val = C::scalar_from_u64(alist.max_accounts.into());
    msgs.push(PsSigMsg::Known);
    secrets.push(PsSigWitnessMsg::Known(Value::new(max_accounts_val)));

    let mut attributes = BTreeMap::new();
    let mut attribute_cmm_rand = BTreeMap::new();
    // Iterate attributes in the same order as signed by the identity provider (tag order)
    for (tag, attribute) in &alist.alist {
        let value = Value::<C>::new(attribute.to_field_element());
        match attributes_handling.get(tag) {
            Some(IdentityAttributeHandling::Commit) => {
                let (attr_cmm, attr_rand) = commitment_key.commit(&value, csprng);
                msgs.push(PsSigMsg::EqualToCommitment(attr_cmm));
                secrets.push(PsSigWitnessMsg::EqualToCommitment(value, attr_rand.clone()));
                attributes.insert(*tag, IdentityAttribute::Committed(attr_cmm));
                attribute_cmm_rand.insert(*tag, attr_rand);
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

    // Retrieve the identity provider signature unapplying the signature randomness
    let retrieved_sig = id_object
        .get_signature()
        .retrieve(&id_object_use_data.randomness);
    // Prepare a fresh blinded signature for the proof. This way proofs cannot be associated with each other
    // via the signature
    let (blinded_sig, blind_rand) = retrieved_sig.blind(csprng);

    let witness = PsSigWitness {
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
        attribute_cmm_rand,
        blinded_sig,
    };

    Ok((prover, witness, output))
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
>(
    global_context: &GlobalContext<C>,
    ip_context: IpContextOnly<'_, P, C>,
    id_attr_info: &IdentityAttributesCredentialsInfo<P, C, AttributeType>,
    transcript: &mut RandomOracle,
) -> Result<(), AttributeCommitmentVerificationError> {
    if ip_context.ip_info.ip_identity != id_attr_info.values.ip_identity {
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

    let verifier_sig = signature_knowledge_verifier(
        &global_context.on_chain_commitment_key,
        &ip_context.ip_info.ip_verify_key,
        id_attr_info,
    )
    .ok_or(AttributeCommitmentVerificationError::Signature)?;

    // Create verifiers for encryption of IdCredSec
    let (id_cred_pub_verifier, id_cred_pub_responses) = id_cred_pub_verifier(
        &global_context.on_chain_commitment_key,
        ip_context.ars_infos,
        &id_attr_info.values.ar_data,
        &id_attr_info
            .proofs
            .commitments
            .cmm_id_cred_sec_sharing_coeff,
        &id_attr_info.proofs.proof_id_cred_pub,
    )?;

    // We "and" the signature proof of knowledge and the IdCredSec share encryption verifiers.
    // The commitment to the coefficients of the sharing polynomial bind the proofs together
    // such that we actually verify that the signed IdCredSec is what is encrypted in the shares.
    let verifier = AndAdapter {
        first: verifier_sig,
        second: id_cred_pub_verifier,
    };
    let response = AndResponse {
        r1: id_attr_info.proofs.proof_ip_signature.clone(),
        r2: id_cred_pub_responses,
    };
    let proof = SigmaProof {
        challenge: id_attr_info.proofs.challenge,
        response,
    };

    if !sigma_protocols::common::verify(transcript, &verifier, &proof) {
        return Err(AttributeCommitmentVerificationError::Proof);
    }

    Ok(())
}

/// verify id_cred data
fn id_cred_pub_verifier<C: Curve>(
    commitment_key: &CommitmentKey<C>,
    known_ars: &BTreeMap<ArIdentity, ArInfo<C>>,
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
fn signature_knowledge_verifier<
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
            .first()?,
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

    // Attribute tag set is just verified known
    msgs.push(PsSigMsg::Known);

    // Max accounts is not public, we verify knowledge of it
    msgs.push(PsSigMsg::Known);

    // Iterate attributes in the same order as signed by the identity provider (tag order)
    for attribute in id_attr_info.values.attributes.values() {
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
        blinded_sig: id_attr_info.proofs.signature.clone(),
        msgs,
        ps_pub_key: ip_pub_key.clone(),
        cmm_key: *commitment_key,
    })
}

#[cfg(test)]
mod test {
    use crate::curve_arithmetic::Value;
    use crate::elgamal::Message;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::identity_attributes_credentials::{
        prove_identity_attributes, verify_identity_attributes,
        AttributeCommitmentVerificationError, IdentityAttributeHandling,
    };
    use crate::id::test::ExampleAttributeList;
    use crate::id::types::{
        ArIdentity, ArInfo, Attribute, AttributeTag, GlobalContext, IdObjectUseData,
        IdentityAttribute, IdentityAttributesCredentialsInfo, IdentityObjectV1, IpContextOnly,
        IpData, IpInfo, YearMonth,
    };
    use crate::id::{identity_provider, test};
    use crate::random_oracle::RandomOracle;
    use assert_matches::assert_matches;
    use std::collections::BTreeMap;

    use crate::common;
    use crate::curve_arithmetic::arkworks_instances::ArkGroup;
    use ark_bls12_381::G1Projective;
    use rand::SeedableRng;
    use std::str::FromStr;
    use std::sync::LazyLock;

    type G1 = ArkGroup<G1Projective>;
    type Bls12 = ark_ec::models::bls12::Bls12<ark_bls12_381::Config>;

    struct IdentityObjectFixture {
        id_object: IdentityObjectV1<IpPairing, ArCurve, AttributeKind>,
        id_use_data: IdObjectUseData<IpPairing, ArCurve>,
        ip_info: IpInfo<IpPairing>,
        ars_infos: BTreeMap<ArIdentity, ArInfo<ArCurve>>,
        global_ctx: GlobalContext<ArCurve>,
    }

    const TAG_0: AttributeTag = AttributeTag(0u8);
    static VALUE_0: LazyLock<AttributeKind> = LazyLock::new(|| AttributeKind::from(55));

    const TAG_1: AttributeTag = AttributeTag(2u8);
    static VALUE_1: LazyLock<AttributeKind> =
        LazyLock::new(|| AttributeKind::from_str("test1").unwrap());

    const TAG_2: AttributeTag = AttributeTag(5u8);
    static VALUE_2: LazyLock<AttributeKind> = LazyLock::new(|| AttributeKind::from(31));

    fn test_create_attributes() -> ExampleAttributeList {
        let mut alist = BTreeMap::new();
        alist.insert(TAG_0, VALUE_0.clone());
        alist.insert(TAG_1, VALUE_1.clone());
        alist.insert(TAG_2, VALUE_2.clone());

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

    fn seed0() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }

    /// Create identity object for use in tests
    fn identity_object_fixture() -> IdentityObjectFixture {
        let max_attrs = 10;
        let num_ars = 5;
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ..
        } = test::test_create_ip_info(&mut seed0(), num_ars, max_attrs);

        let global_ctx = GlobalContext::generate(String::from("genesis_string"));

        let (ars_infos, _ars_secret) =
            test::test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut seed0());

        let id_use_data = test::test_create_id_use_data(&mut seed0());
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

    fn ip_context(
        id_object_fixture: &IdentityObjectFixture,
    ) -> IpContextOnly<'_, IpPairing, ArCurve> {
        IpContextOnly {
            ip_info: &id_object_fixture.ip_info,
            ars_infos: &id_object_fixture.ars_infos,
        }
    }

    /// Test that the verifier accepts a valid proof when commiting to attributes
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
        let (id_attr_info, rand) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        assert_matches!(id_attr_info.values.attributes.get(&TAG_0), Some(IdentityAttribute::Committed(c)) => {
            let r= rand.attributes_rand.get(&TAG_0).expect("rand");
            assert!(id_object_fixture.global_ctx.on_chain_commitment_key.open(&Value::new(VALUE_0.to_field_element()), r, c));
        });
        assert_matches!(id_attr_info.values.attributes.get(&TAG_1), Some(IdentityAttribute::Committed(c)) => {
            let r= rand.attributes_rand.get(&TAG_1).expect("rand");
            assert!(id_object_fixture.global_ctx.on_chain_commitment_key.open(&Value::new(VALUE_1.to_field_element()), r, c));
        });
        assert_matches!(id_attr_info.values.attributes.get(&TAG_2), Some(IdentityAttribute::Committed(c)) => {
            let r= rand.attributes_rand.get(&TAG_2).expect("rand");
            assert!(id_object_fixture.global_ctx.on_chain_commitment_key.open(&Value::new(VALUE_2.to_field_element()), r, c));
        });

        let mut transcript = RandomOracle::empty();
        verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        )
        .expect("verify");
    }

    /// Test that the verifier accepts a valid proof when revealing attributes
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
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        assert_matches!(id_attr_info.values.attributes.get(&TAG_0), Some(IdentityAttribute::Revealed(a)) => {
            assert_eq!(a, &*VALUE_0);
        });
        assert_matches!(id_attr_info.values.attributes.get(&TAG_1), Some(IdentityAttribute::Revealed(a)) => {
            assert_eq!(a, &*VALUE_1);
        });
        assert_matches!(id_attr_info.values.attributes.get(&TAG_2), Some(IdentityAttribute::Revealed(a)) => {
            assert_eq!(a, &*VALUE_2);
        });

        let mut transcript = RandomOracle::empty();
        verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        )
        .expect("verify");
    }

    /// Test that the verifier accepts a valid proof when just proving all attributes known
    #[test]
    pub fn test_identity_attributes_completeness_empty() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        assert_matches!(
            id_attr_info.values.attributes.get(&TAG_0),
            Some(IdentityAttribute::Known)
        );
        assert_matches!(
            id_attr_info.values.attributes.get(&TAG_1),
            Some(IdentityAttribute::Known)
        );
        assert_matches!(
            id_attr_info.values.attributes.get(&TAG_2),
            Some(IdentityAttribute::Known)
        );

        let mut transcript = RandomOracle::empty();
        verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        )
        .expect("verify");
    }

    /// Test that the verifier accepts a valid proof when mixing how attributes are handled
    #[test]
    pub fn test_identity_attributes_completeness_mixed() {
        let id_object_fixture = identity_object_fixture();

        let mut attributes_handling = BTreeMap::new();
        attributes_handling.insert(TAG_0, IdentityAttributeHandling::Commit);
        attributes_handling.insert(TAG_1, IdentityAttributeHandling::Reveal);

        let mut transcript = RandomOracle::empty();
        let (id_attr_info, rand) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        assert_matches!(id_attr_info.values.attributes.get(&TAG_0), Some(IdentityAttribute::Committed(c)) => {
            let r= rand.attributes_rand.get(&TAG_0).expect("rand");
            assert!(id_object_fixture.global_ctx.on_chain_commitment_key.open(&Value::new(VALUE_0.to_field_element()), r, c));
        });
        assert_matches!(id_attr_info.values.attributes.get(&TAG_1), Some(IdentityAttribute::Revealed(a)) => {
            assert_eq!(a, &*VALUE_1);
        });
        assert_matches!(
            id_attr_info.values.attributes.get(&TAG_2),
            Some(IdentityAttribute::Known)
        );

        let mut transcript = RandomOracle::empty();
        verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        )
        .expect("verify");
    }

    /// Test that the verifier does not accept the proof if the
    /// id cred pub encryption is not what is signed by the identity provider
    #[test]
    pub fn test_identity_attributes_soundness_ar_shares_encryption() {
        let mut csprng = rand::thread_rng();

        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // make one of the ar share encryptions invalid
        let ar = *id_attr_info.values.ar_data.keys().next().unwrap();
        let enc = id_attr_info.values.ar_data.get_mut(&ar).unwrap();
        let ar_info = id_object_fixture.ars_infos.get(&ar).unwrap();
        let new_message = Message::generate(&mut csprng);
        enc.enc_id_cred_pub_share = ar_info.ar_public_key.encrypt(&mut csprng, &new_message);

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );

        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that the verifier does not accept the proof if the
    /// id cred pub encryption has share missing for an ar
    #[test]
    pub fn test_identity_attributes_soundness_ar_shares_encryption_remove_ar() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // remove one of the encryptions
        let ar = *id_attr_info.values.ar_data.keys().next().unwrap();
        id_attr_info.values.ar_data.remove(&ar);

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );

        assert_matches!(res, Err(AttributeCommitmentVerificationError::IdCredPub));
    }

    /// Test that the verifier fails if identity provider is not set correctly.
    #[test]
    pub fn test_identity_attributes_soundness_ip() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
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
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Signature));
    }

    /// Test that the verifier does not accept the proof if the
    /// identity provider signature does not match the values in the identity attribute credentials.
    #[test]
    pub fn test_identity_attributes_soundness_ip_signature_ar_threshold() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // decrease ar threshold
        id_attr_info.values.threshold.0 -= 1;
        id_attr_info
            .proofs
            .commitments
            .cmm_id_cred_sec_sharing_coeff
            .pop();

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that the verifier does not accept the proof if the
    /// identity provider signature does not match the values in the identity attribute credentials.
    #[test]
    pub fn test_identity_attributes_soundness_ip_signature_ar_ids() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // remove one of the ars
        let ar_to_remove = *id_attr_info.values.ar_data.keys().next().unwrap();
        id_attr_info.values.ar_data.remove(&ar_to_remove);
        id_attr_info.proofs.proof_id_cred_pub.remove(&ar_to_remove);

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that the verifier does not accept the proof if the
    /// identity provider signature does not match the values in the identity attribute credentials.
    #[test]
    pub fn test_identity_attributes_soundness_ip_signature_created_at() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // change created at
        id_attr_info.values.validity.created_at = YearMonth::try_from(2025 << 8 | 5).unwrap();

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that the verifier does not accept the proof if the
    /// identity provider signature does not match the values in the identity attribute credentials.
    #[test]
    pub fn test_identity_attributes_soundness_ip_signature_valid_to() {
        let id_object_fixture = identity_object_fixture();

        let attributes_handling = BTreeMap::new();
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // change valid to
        id_attr_info.values.validity.valid_to = YearMonth::try_from(2025 << 8 | 5).unwrap();

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that the verifier does not accept the proof if the
    /// identity provider signature does not match the values in the identity attribute credentials.
    #[test]
    pub fn test_identity_attributes_soundness_ip_signature_revealed_attribute() {
        let id_object_fixture = identity_object_fixture();

        let mut attributes_handling = BTreeMap::new();
        attributes_handling.insert(TAG_0, IdentityAttributeHandling::Reveal);
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // change revealed value
        assert_matches!(id_attr_info.values.attributes.get_mut(&TAG_0).unwrap(), IdentityAttribute::Revealed(a) => {
            *a = AttributeKind::from_str("someotherstring").unwrap()
        });

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that the verifier does not accept the proof if the
    /// identity provider signature does not match the values in the identity attribute credentials.
    #[test]
    pub fn test_identity_attributes_soundness_ip_signature_commited_attribute() {
        let mut csprng = rand::thread_rng();

        let id_object_fixture = identity_object_fixture();

        let mut attributes_handling = BTreeMap::new();
        attributes_handling.insert(TAG_0, IdentityAttributeHandling::Commit);
        let mut transcript = RandomOracle::empty();
        let (mut id_attr_info, _) = prove_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_object_fixture.id_object,
            &id_object_fixture.id_use_data,
            &attributes_handling,
            &mut transcript,
        )
        .expect("prove");

        // change attribute commitment
        assert_matches!(id_attr_info.values.attributes.get_mut(&TAG_0).unwrap(), IdentityAttribute::Committed(c) => {
            let a = AttributeKind::from_str("someotherstring").unwrap();
            let (new_c, _r) = id_object_fixture.global_ctx.on_chain_commitment_key.commit(&Value::<G1>::new(a.to_field_element()), &mut csprng);
            *c = new_c;
        });

        let mut transcript = RandomOracle::empty();
        let res = verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        );
        assert_matches!(res, Err(AttributeCommitmentVerificationError::Proof));
    }

    /// Test that we can verify proofs created by previous versions of the protocol.
    /// This test protects from changes that introduces braking changes without proper versioning.
    ///
    /// The test uses a serialization of a previously created proof.
    #[test]
    pub fn test_identity_attributes_stable() {
        let id_object_fixture = identity_object_fixture();

        // Comment out to regenerate proof. We can do that as long as we have not released yet
        //
        // let mut attributes_handling = BTreeMap::new();
        // attributes_handling.insert(TAG_0, IdentityAttributeHandling::Commit);
        // attributes_handling.insert(TAG_1, IdentityAttributeHandling::Reveal);
        //
        // let mut transcript = RandomOracle::empty();
        // let (id_attr_info, rand) = prove_identity_attributes(
        //     &id_object_fixture.global_ctx,
        //     ip_context(&id_object_fixture),
        //     &id_object_fixture.id_object,
        //     &id_object_fixture.id_use_data,
        //     &attributes_handling,
        //     &mut transcript,
        // )
        // .expect("prove");
        //
        // let proof_bytes_hex = hex::encode(common::to_bytes(&id_attr_info));
        // assert_eq!(proof_bytes_hex, "");

        let proof_bytes_hex = "0000000004000500000001b1e598e73ec0a06a4e68a643083d7146f9155414b428efd0dc39758adc6e7a2dba718d456a03b3fc2de66ed09170c778951b05efd8044b6f2a74397d57ec0c2b5fc5758fb4dfd3f811b4ab149a375e226c74373bcf235c72e19e8f689a2df8e900000002b7d95f164d44215f908e1a2f74887d336200a9444f760d5700004341a1a5e43690b24445ff090deb68b40340c34bff26b27fb696a056d0ac25b0605c3b234616bee6456191d1b9382119e63bb610ebfdab536c16aefb432b4cfe88956162dcbf00000003b8e6654ab88938e076b172816b61bd0da83ccb47d460128e74d8170d6a37b14c4945fcad34c9550231179c968f90fce5b11b713b44da97b5ffb02c14b4d797eabcbd8970f1dad96a0bc0758a5a685e66f2f9ea89dee66816cf3d5f1d0b4e218b00000004b8bbc524fe3b4112167c8ea7f92c5212a94914ab7be792a342648d5b562f210a4c4de257ac48486441c117df7dc8de8ab8f4a745961bd0ad3212087cb15d6b6f3dbe19c56be728bdd508ef5aeeb610d5ea10a64f078f6b21a871ebe86da6737c00000005929d59d7894d007f71c9e382689cb2086c8b0caf188cdd31fcd8138ffddd76a0b614a22162a51d4e2b795f919be3af7f8d8049a086121762dcccc4883651339954ba985b532efe4f0c40680d210cc0f93065790a4334b3d49ef67bf1c172929e000300008e7a1c2f48419f19dc97751937a2d1c3163c4546aa45ce37863f37a54c1d43d2f5a9646b031a1ead25980cc6cdf94a2b0201057465737431050207e60507e405a3eb4da90047ef8ecda05e0c3f6b57659fb2f3550fab1285628f7192d8ae135f22defc274a0e9dadf98b226507ae8a1d991eed12b245373698522784cd8ff32718fbb9f4b4794b57ace9d9d2dbac445366d7e424fd15eba1b5ddb5fa47c2fcb800000000000000048b1440e9efd587181ce32b8864b9c6287adb0fa24662118f0089d99a57b611b9596d33a5fd04fd0024840ce1002b7fb586ac9f85236780ea53f280f3820d0be385b6d4400dc028e940569d1f31cc0486a024ec8f302790e5ffe7b40a9fcb9bb6917e34ac78b6482a3089324cdea492f6a8287e3a1993f248a1db590af49fc3f7ec9c8c97429c809286672f5e88ba33648237b5833480623e5e88d7de54cb53e6c1b40a4642aaf002fdb1e1b8e615037143ac72c2dca990c1aef279f2ee0e6e27a759129fb5b196774d66e9f5f219fe183160091d6eccb7cc63040a621e771b37000000050000000109ea4726659a439f89b3356bd4001ebad9e2901868a996b5295bfe75f995990f4aca3be89c4e25ee69cda09084c2b3eca3c54fdd8b370ba17fc5c0210a3fbb622268ccfe2ee1091f53725febc54986efe2bedbb7b49c390417652187797312880000000273aea54c713d331c75949c1858aaa26a8be88ed9f0024fb7f03aed7630dcdc7b1641b162ab90f2096c29dc8bd1cac00e833c759407ec866f5162ea31d296a09858bc342c5c75c523c8d31c0570025bb0485811b8b22ad72f6a8f5f67c6cf21780000000332b1a857a9c89bb4dc2fa09f1caa1d8e4e46550fa16e97e56c83955b32d4375a110e749d8a704e3152514c310ea20e62d8a9183efee6c3766888b49dbc1970652088cca07655ec588df869e4d609db645cb2b266f816fbfe3327aa05e29977ae00000004409dbba015e514777740d9dc39b79b46f0fa569c974931c317ad661b852d7adb33a7192ff305a48b8ebecb8b35c4eca59239fbc07b7ea09c4fe6c0d3159ad97c40b41a6fec9262088c5b50a4874a267160683e6fae4111252f4346528c7ff3d2000000054b408170b31dfa73767e9ea56eab38f04bd10be7c69d60df6b6b9e28e6edb7ea536fce8c1c7b76a9e3b99a842de20cc8f8bcf84f6dddca2a650bb4ccc3cab3bf0c67ab96dcabe3d6b103857e492d2704c5fa1fbc01181b3268d75de80af7e8440bbac55533e357d3c0c94009b1aecd6f19b33414c307478a66960d098564cb8e00000009004809112af37ee003339e4a7095f86aad64bb5d202ad610f7ac3b79c36e29522b62db69a6236c5d6f5f8a252a567d1911abbe7322077ddefa73dc8af086044f86023f5964a47841261fec78b59f361443903606fcf8c150e6a587f46c2003dac7b701010202329315e825b6b0f079289ff6cc82d40e0198f601060d78faabeecc4d70ce4e027262d15a64182e33c45d3137c65cf3904b2d66b75b94e5cdf5ea54786a193387006357bbbd9d1d48a41c6e6f1dc764218bbbe8e68214b57d184063b5eb1eabdb312a249a04064d8963b8ecf84baf6e3d7b1cc384b6903f1cd2e7f4652fd0eea5110102281969f31040c1107fa839908acb5f6186d5a9ab0f746b084d90cabc9c2bee24";
        let proof_bytes = hex::decode(&proof_bytes_hex).unwrap();
        let id_attr_info: IdentityAttributesCredentialsInfo<Bls12, G1, AttributeKind> =
            common::from_bytes(&mut proof_bytes.as_slice()).expect("deserialize");

        let mut transcript = RandomOracle::empty();
        verify_identity_attributes(
            &id_object_fixture.global_ctx,
            ip_context(&id_object_fixture),
            &id_attr_info,
            &mut transcript,
        )
        .expect("verify");
    }
}
