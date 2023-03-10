//! Functionality needed by the chain to verify credential deployments.
use crate::{
    secret_sharing::Threshold,
    sigma_protocols::{com_enc_eq, com_eq_sig, com_mult, common::*},
    types::*,
    utils,
};
use bulletproofs::range_proof::verify_less_than_or_equal;
use core::fmt::{self, Display};
use crypto_common::{to_bytes, types::TransactionTime};
use curve_arithmetic::{Curve, Pairing};
use ed25519_dalek::Verifier;
use either::Either;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use random_oracle::RandomOracle;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reason why verification of a credential failed.
pub enum CdiVerificationError {
    RegId,
    IdCredPub,
    Signature,
    Dlog,
    AccountOwnership,
    Policy,
    Ar,
    Proof,
}

impl Display for CdiVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CdiVerificationError::RegId => write!(f, "RegIdVerificationError"),
            CdiVerificationError::IdCredPub => write!(f, "IdCredPubVerificationError"),
            CdiVerificationError::Signature => write!(f, "SignatureVerificationError"),
            CdiVerificationError::Dlog => write!(f, "DlogVerificationError"),
            CdiVerificationError::AccountOwnership => write!(f, "AccountOwnership"),
            CdiVerificationError::Policy => write!(f, "PolicyVerificationError"),
            CdiVerificationError::Ar => write!(f, "AnonymityRevokerVerificationError"),
            CdiVerificationError::Proof => write!(f, "ProofVerificationError"),
        }
    }
}
/// Verify credential deployment info. This checks that the data is consistent,
/// and that the credential is signed by the specified identity provider.
pub fn verify_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
    A: HasArPublicKey<C>,
>(
    global_context: &GlobalContext<C>,
    ip_info: &IpInfo<P>,
    // NB: The following map only needs to be a superset of the ars
    // in the cdi.
    known_ars: &BTreeMap<ArIdentity, A>,
    cdi: &CredentialDeploymentInfo<P, C, AttributeType>,
    new_or_existing: &Either<TransactionTime, AccountAddress>,
) -> Result<(), CdiVerificationError> {
    // We need to check that the threshold is actually equal to
    // the number of coefficients in the sharing polynomial
    // (corresponding to the degree+1)
    let addr = new_or_existing.as_ref().right();
    let rt_usize: usize = cdi.values.threshold.into();
    if rt_usize
        != cdi
            .proofs
            .id_proofs
            .commitments
            .cmm_id_cred_sec_sharing_coeff
            .len()
    {
        return Err(CdiVerificationError::Ar);
    }
    let on_chain_commitment_key = global_context.on_chain_commitment_key;
    let gens = global_context.bulletproof_generators();
    let ip_verify_key = &ip_info.ip_verify_key;
    // Compute the challenge prefix by hashing the values.
    let mut ro = RandomOracle::domain("credential");
    ro.append_message(b"cred_values", &cdi.values);
    ro.append_message(b"address", &addr);
    ro.append_message(b"global_context", &global_context);

    let commitments = &cdi.proofs.id_proofs.commitments;

    // We now need to construct a uniform verifier
    // since we cannot check proofs independently.

    let verifier_reg_id = com_mult::ComMult {
        cmms:    [
            commitments.cmm_prf.combine(&commitments.cmm_cred_counter),
            Commitment(cdi.values.cred_id),
            Commitment(on_chain_commitment_key.g),
        ],
        cmm_key: on_chain_commitment_key,
    };
    // FIXME: Figure out a pattern to get rid of these clone's.
    let witness_reg_id = cdi.proofs.id_proofs.proof_reg_id.clone();

    let cdv = &cdi.values;
    let proofs = &cdi.proofs;

    let verifier_sig = pok_sig_verifier(
        &on_chain_commitment_key,
        cdi.values.threshold,
        &cdi.values
            .ar_data
            .keys()
            .copied()
            .collect::<BTreeSet<ArIdentity>>(),
        &cdi.values.policy,
        commitments,
        ip_verify_key,
        &cdi.proofs.id_proofs.sig,
    );
    let verifier_sig = if let Some(v) = verifier_sig {
        v
    } else {
        return Err(CdiVerificationError::Signature);
    };

    let witness_sig = cdi.proofs.id_proofs.proof_ip_sig.clone();

    let (id_cred_pub_verifier, id_cred_pub_witnesses) = id_cred_pub_verifier(
        &on_chain_commitment_key,
        known_ars,
        &cdi.values.ar_data,
        &commitments.cmm_id_cred_sec_sharing_coeff,
        &cdi.proofs.id_proofs.proof_id_cred_pub,
    )?;

    let verifier = AndAdapter {
        first:  verifier_reg_id,
        second: verifier_sig,
    };
    let verifier = verifier.add_prover(id_cred_pub_verifier);
    let witness = AndWitness {
        w1: AndWitness {
            w1: witness_reg_id,
            w2: witness_sig,
        },
        w2: id_cred_pub_witnesses,
    };
    let proof = SigmaProof {
        challenge: cdi.proofs.id_proofs.challenge,
        witness,
    };

    if !verify(&mut ro, &verifier, &proof) {
        return Err(CdiVerificationError::Proof);
    }

    if !verify_less_than_or_equal(
        &mut ro,
        8,
        &cdi.proofs.id_proofs.commitments.cmm_cred_counter,
        &cdi.proofs.id_proofs.commitments.cmm_max_accounts,
        &cdi.proofs.id_proofs.cred_counter_less_than_max_accounts,
        gens,
        &on_chain_commitment_key,
    ) {
        return Err(CdiVerificationError::Proof);
    }
    let signed = utils::credential_hash_to_sign(cdv, &proofs.id_proofs, new_or_existing);
    // Notice that here we provide all the verification keys, and the
    // function `verify_accunt_ownership_proof` assumes that
    // we have as many signatures as verification keys.
    if !utils::verify_account_ownership_proof(
        &cdv.cred_key_info.keys,
        cdv.cred_key_info.threshold,
        &proofs.proof_acc_sk,
        signed.as_ref(),
    ) {
        return Err(CdiVerificationError::AccountOwnership);
    }

    let check_policy = verify_policy(&on_chain_commitment_key, commitments, &cdi.values.policy);

    if !check_policy {
        return Err(CdiVerificationError::Policy);
    }

    Ok(())
}

/// Verify initial account creation. This is essentially checking that the
/// signature by the identity provider is correct.
pub fn verify_initial_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    ip_info: &IpInfo<P>,
    cdi: &InitialCredentialDeploymentInfo<C, AttributeType>,
    expiry: TransactionTime,
) -> Result<(), CdiVerificationError> {
    let mut hasher = Sha256::new();
    hasher.update(&to_bytes(&expiry));
    hasher.update(&to_bytes(&cdi.values));
    let signed = hasher.finalize();
    match ip_info.ip_cdi_verify_key.verify(signed.as_ref(), &cdi.sig) {
        Err(_) => Err(CdiVerificationError::Signature),
        _ => Ok(()),
    }
}

/// verify id_cred data
fn id_cred_pub_verifier<C: Curve, A: HasArPublicKey<C>>(
    commitment_key: &CommitmentKey<C>,
    known_ars: &BTreeMap<ArIdentity, A>,
    chain_ar_data: &BTreeMap<ArIdentity, ChainArData<C>>,
    cmm_sharing_coeff: &[Commitment<C>],
    proof_id_cred_pub: &BTreeMap<ArIdentity, com_enc_eq::Witness<C>>,
) -> Result<IdCredPubVerifiers<C>, CdiVerificationError> {
    let mut provers = Vec::with_capacity(proof_id_cred_pub.len());
    let mut witnesses = Vec::with_capacity(proof_id_cred_pub.len());

    // The encryptions and the proofs have to match.
    if chain_ar_data.len() != proof_id_cred_pub.len() {
        return Err(CdiVerificationError::IdCredPub);
    }

    // The following relies on the fact that iterators over BTreeMap are
    // over sorted values.
    for ((ar_id, ar_data), (ar_id_1, witness)) in chain_ar_data.iter().zip(proof_id_cred_pub.iter())
    {
        if ar_id != ar_id_1 {
            return Err(CdiVerificationError::IdCredPub);
        }
        let cmm_share = utils::commitment_to_share(&ar_id.to_scalar::<C>(), cmm_sharing_coeff);

        // finding the correct AR data.
        let ar_info = known_ars
            .get(ar_id)
            .ok_or(CdiVerificationError::IdCredPub)?;
        let item_prover = com_enc_eq::ComEncEq {
            cipher: ar_data.enc_id_cred_pub_share,
            commitment: cmm_share,
            pub_key: *ar_info.get_public_key(),
            cmm_key: *commitment_key,
            encryption_in_exponent_generator: ar_info.get_public_key().generator,
        };
        provers.push(item_prover);
        witnesses.push(witness.clone());
    }
    Ok((ReplicateAdapter { protocols: provers }, ReplicateWitness {
        witnesses,
    }))
}

/// Verify a policy. This currently does not do anything since
/// the only check that is done is that the commitments are opened correctly,
/// and that check is part of the signature check.
fn verify_policy<C: Curve, AttributeType: Attribute<C::Scalar>>(
    _commitment_key: &CommitmentKey<C>,
    _commitments: &CredentialDeploymentCommitments<C>,
    _policy: &Policy<C, AttributeType>,
) -> bool {
    true
}

/// Verify the proof of knowledge of signature on the attribute list.
/// A none return value means we cannot construct a verifier, and consequently
/// it should be interperted as the signature being invalid.
#[allow(clippy::too_many_arguments)]
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
    commitments: &'a CredentialDeploymentCommitments<C>,
    ip_pub_key: &'a ps_sig::PublicKey<P>,
    blinded_sig: &'a ps_sig::BlindedSignature<P>,
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
        // FIXME: Figure out how to restructure to get rid of this clone.
        blinded_sig: blinded_sig.clone(),
        commitments: comm_vec,
        // FIXME: Figure out how to restructure to get rid of this clone.
        ps_pub_key:  ip_pub_key.clone(),
        comm_key:    *commitment_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{account_holder::*, constants::*, identity_provider::*, test::*};
    use crypto_common::types::{KeyIndex, KeyPair};
    use pairing::bls12_381::G1;
    use rand::*;
    use std::collections::btree_map::BTreeMap;
    use Either::{Left, Right};

    const EXPIRY: TransactionTime = TransactionTime {
        seconds: 111111111111111111,
    };

    #[test]
    fn test_verify_cdi() {
        let mut csprng = thread_rng();

        // Generate PIO
        let max_attrs = 10;
        let num_ars = 5;
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ip_cdi_secret_key,
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<G1>::generate(String::from("genesis_string"));
        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);
        let id_use_data = test_create_id_use_data(&mut csprng);
        let initial_acc_data = InitialAccountData {
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
            &initial_acc_data,
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
        assert!(ver_ok.is_ok());

        // Generate CDI
        let (ip_sig, _) = ver_ok.unwrap();
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
        let cred_data = CredentialData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
                keys
            },
            threshold: SignatureThreshold(2),
        };
        let context = IpContext::new(&ip_info, &ars_infos, &global_ctx);
        let (cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            0,
            policy.clone(),
            &cred_data,
            &SystemAttributeRandomness {},
            &Left(EXPIRY),
        )
        .expect("Should generate the credential successfully.");
        let cdi_check = verify_cdi(&global_ctx, &ip_info, &ars_infos, &cdi, &Left(EXPIRY));
        assert_eq!(cdi_check, Ok(()));

        // Testing with an existing RegId (i.e. an existing account)
        let existing_reg_id = account_address_from_registration_id(&cdi.values.cred_id);
        let cred_data = CredentialData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
                keys
            },
            threshold: SignatureThreshold(2),
        };
        let (cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            1,
            policy,
            &cred_data,
            &SystemAttributeRandomness {},
            &Right(existing_reg_id),
        )
        .expect("Should generate the credential successfully.");
        let cdi_check = verify_cdi(
            &global_ctx,
            &ip_info,
            &ars_infos,
            &cdi,
            &Right(existing_reg_id),
        );
        assert_eq!(cdi_check, Ok(()));
    }

    /// This tests the credential creation flow, where no initial account was
    /// involved in the identity creation process.
    #[test]
    fn test_verify_cdi_v1() {
        let mut csprng = thread_rng();

        // Generate PIO
        let max_attrs = 10;
        let num_ars = 5;
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            .. // ip_cdi_secret_key is not used since we are testing the flow without initial account creation
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<G1>::generate(String::from("genesis_string"));
        let (ars_infos, _) =
            test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);
        let id_use_data = test_create_id_use_data(&mut csprng);
        let (context, pio, randomness) =
            test_create_pio_v1(&id_use_data, &ip_info, &ars_infos, &global_ctx, num_ars);
        assert_eq!(*randomness, *(id_use_data.randomness));
        let alist = test_create_attributes();
        let ver_ok = verify_credentials_v1(&pio, context, &alist, &ip_secret_key);
        assert!(ver_ok.is_ok());

        // Generate CDI
        let ip_sig = ver_ok.unwrap();
        let id_object = IdentityObjectV1 {
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
        let cred_data = CredentialData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
                keys
            },
            threshold: SignatureThreshold(2),
        };
        let context = IpContext::new(&ip_info, &ars_infos, &global_ctx);
        let (cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            0,
            policy.clone(),
            &cred_data,
            &SystemAttributeRandomness {},
            &Left(EXPIRY),
        )
        .expect("Should generate the credential successfully.");
        let cdi_check = verify_cdi(&global_ctx, &ip_info, &ars_infos, &cdi, &Left(EXPIRY));
        assert_eq!(cdi_check, Ok(()));

        // Testing with an existing RegId (i.e. an existing account)
        let existing_reg_id = account_address_from_registration_id(&cdi.values.cred_id);
        let cred_data = CredentialData {
            keys:      {
                let mut keys = BTreeMap::new();
                keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
                keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
                keys
            },
            threshold: SignatureThreshold(2),
        };
        let (cdi, _) = create_credential(
            context,
            &id_object,
            &id_use_data,
            1,
            policy,
            &cred_data,
            &SystemAttributeRandomness {},
            &Right(existing_reg_id),
        )
        .expect("Should generate the credential successfully.");
        let cdi_check = verify_cdi(
            &global_ctx,
            &ip_info,
            &ars_infos,
            &cdi,
            &Right(existing_reg_id),
        );
        assert_eq!(cdi_check, Ok(()));
    }

    #[test]
    fn test_verify_initial_cdi() {
        let mut csprng = thread_rng();

        // Generate PIO
        let max_attrs = 10;
        let num_ars = 5;
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ip_cdi_secret_key,
        } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let global_ctx = GlobalContext::<G1>::generate(String::from("genesis_string"));
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
        let alist = test_create_attributes();
        let ver_ok = verify_credentials(
            &pio,
            context,
            &alist,
            EXPIRY,
            &ip_secret_key,
            &ip_cdi_secret_key,
        );
        assert!(ver_ok.is_ok());

        // Verify initial CDI
        let (_, initial_cdi) = ver_ok.unwrap();
        let cdi_check = verify_initial_cdi(&ip_info, &initial_cdi, EXPIRY);
        assert_eq!(cdi_check, Ok(()));
    }
}
