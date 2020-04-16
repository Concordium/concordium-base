use crate::types::*;

use failure::Fallible;

use random_oracle::RandomOracle;

use crate::{
    secret_sharing::*,
    sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult, dlog},
};
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use either::Either;
use elgamal::cipher::Cipher;
use ff::Field;
use pedersen_scheme::{
    commitment::Commitment, key::CommitmentKey as PedersenKey,
    randomness::Randomness as PedersenRandomness, value as pedersen, value::Value,
};
use ps_sig;
use rand::{rngs::ThreadRng, *};
use std::collections::{btree_map::BTreeMap, hash_map::HashMap};

/// Generate PreIdentityObject out of the account holder information,
/// the chosen anonymity revoker information, and the necessary contextual
/// information (group generators, shared commitment keys, etc).
pub fn generate_pio<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    context: &Context<P, C>,
    aci: &AccCredentialInfo<C>,
) -> (PreIdentityObject<P, C>, ps_sig::SigRetrievalRandomness<P>) {
    let mut csprng = thread_rng();
    let id_cred_pub = context
        .ip_info
        .ip_ars
        .ar_base
        .mul_by_scalar(&aci.cred_holder_info.id_cred.id_cred_sec);

    // PRF related computation
    let prf::SecretKey(prf_key_scalar) = aci.prf_key;
    // FIXME: The next item will change to encrypt by chunks to enable anonymity
    // revocation.
    // sharing data, commitments to sharing coefficients, and randomness of the
    // commitments sharing data is a list of SingleArData
    let prf_value = Value::new(aci.prf_key.0);

    let (prf_key_data, cmm_prf_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data(
        &prf_value,
        &context.choice_ar_parameters,
        &context.ip_info.ip_ars.ar_cmm_key,
    );
    let number_of_ars = context.choice_ar_parameters.0.len();
    let mut ip_ar_data: Vec<IpArData<C>> = Vec::with_capacity(number_of_ars);
    let ar_commitment_key = context.ip_info.ip_ars.ar_cmm_key;

    // Fill IpArData with data for each anonymity revoker
    //   - The AR id
    //   - An encryption under AR publickey of his share of the PRF key
    //   - The ARs share number (x-coordinate of polynomial)
    //   - ZK-proof that the encryption has same value as corresponding commitment
    for item in prf_key_data.iter() {
        let secret = com_enc_eq::ComEncEqSecret {
            value: &item.share,
            elgamal_rand: &item.encryption_randomness,
            pedersen_rand: &item.randomness_cmm_to_share,
        };
        // FIXME: Need some context in the challenge computation.
        let proof = com_enc_eq::prove_com_enc_eq(
            RandomOracle::empty(),
            &item.encrypted_share,
            &item.cmm_to_share,
            &item.ar_public_key,
            &ar_commitment_key,
            &secret,
            &mut csprng,
        );
        ip_ar_data.push(IpArData {
            ar_identity: item.ar_identity,
            enc_prf_key_share: item.encrypted_share,
            prf_key_share_number: item.share_number,
            proof_com_enc_eq: proof,
        });
    }

    // Commit and prove knowledge of id_cred_sec
    let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
    let sc_ck = PedersenKey(
        context.ip_info.ip_verify_key.ys[0],
        context.ip_info.ip_verify_key.g,
    );
    let (cmm_sc, cmm_sc_rand) = sc_ck.commit(id_cred_sec.view(), &mut csprng);
    // FIXME: prefix needs to be all the data sent to id provider or some such.
    let pok_sc = dlog::prove_dlog(
        &mut csprng,
        RandomOracle::empty(),
        &id_cred_pub,
        id_cred_sec,
        &context.ip_info.ip_ars.ar_base,
    );

    let proof_com_eq_sc = {
        // FIXME: prefix needs to be all the data sent to the id provider.
        com_eq::prove_com_eq_single(
            RandomOracle::empty(),
            &cmm_sc,
            &id_cred_pub,
            &sc_ck,
            &context.ip_info.ip_ars.ar_base,
            (&cmm_sc_rand, Value::<P::G1>::view_scalar(&id_cred_sec)),
            &mut csprng,
        )
    };

    // Commit to the PRF key for the IP and prove equality for the secret-shared PRF
    // key
    let commitment_key_prf = PedersenKey(
        context.ip_info.ip_verify_key.ys[1],
        context.ip_info.ip_verify_key.g,
    );
    let (cmm_prf, rand_cmm_prf) =
        commitment_key_prf.commit(&pedersen::Value::view_scalar(&prf_key_scalar), &mut csprng);
    let snd_cmm_prf = &cmm_prf_sharing_coeff[0];
    let rand_snd_cmm_prf = &cmm_coeff_randomness[0];
    let proof_com_eq = {
        let secret = com_eq_different_groups::ComEqDiffGrpsSecret {
            value: Value::view_scalar(&prf_key_scalar),
            rand_cmm_1: &rand_cmm_prf,
            rand_cmm_2: rand_snd_cmm_prf,
        };
        com_eq_different_groups::prove_com_eq_diff_grps(
            RandomOracle::empty(),
            &cmm_prf,
            snd_cmm_prf,
            &commitment_key_prf,
            &context.ip_info.ip_ars.ar_cmm_key,
            &secret,
            &mut csprng,
        )
    };

    // Extract identities of the chosen ARs for use in PIO
    let ar_identities = context
        .choice_ar_parameters
        .0
        .iter()
        .map(|x| x.ar_identity)
        .collect();

    let threshold = context.choice_ar_parameters.1;

    // attribute list
    let prio = PreIdentityObject {
        id_cred_pub,
        proof_com_eq_sc,
        ip_ar_data,
        choice_ar_parameters: ChoiceArParameters {
            ar_identities,
            threshold,
        },
        cmm_sc,
        pok_sc,
        cmm_prf,
        cmm_prf_sharing_coeff,
        proof_com_eq,
    };
    // randomness to retrieve the signature
    // We add randomness from both of the commitments.
    // See specification of ps_sig and id layer for why this is so.
    let mut sig_retrieval_rand = cmm_sc_rand.randomness;
    sig_retrieval_rand.add_assign(&rand_cmm_prf);
    (
        prio,
        ps_sig::SigRetrievalRandomness {
            randomness: sig_retrieval_rand,
        },
    )
}

/// Convenient data structure to collect data related to a single AR
pub struct SingleArData<C: Curve> {
    ar_identity: ArIdentity,
    share: Value<C>,
    share_number: ShareNumber,
    encrypted_share: Cipher<C>,
    encryption_randomness: elgamal::Randomness<C>,
    cmm_to_share: Commitment<C>,
    randomness_cmm_to_share: PedersenRandomness<C>,
    ar_public_key: elgamal::PublicKey<C>,
}

type SharingData<C> = (
    Vec<SingleArData<C>>,
    Vec<Commitment<C>>, /* Commitments to the coefficients of sharing polynomial S + b1 X + b2
                         * X^2... */
    Vec<PedersenRandomness<C>>,
);

/// A function to compute sharing data.
pub fn compute_sharing_data<'a, C: Curve>(
    shared_scalar: &'a Value<C>,                 // Value to be shared.
    ar_parameters: &(Vec<ArInfo<C>>, Threshold), // Anonimity revokers
    commitment_key: &PedersenKey<C>,             // commitment key
) -> SharingData<C> {
    let n = ar_parameters.0.len() as u32;
    let t = ar_parameters.1;
    let tu: u32 = t.into();
    let mut csprng = thread_rng();
    // first commit to the scalar
    let (cmm_scalar, cmm_scalar_rand) = commitment_key.commit(&shared_scalar, &mut csprng);
    // share the scalar
    let sharing_data = share::<C, ThreadRng>(&shared_scalar, ShareNumber::from(n), t, &mut csprng);
    // commitments to the sharing coefficients
    let mut cmm_sharing_coefficients: Vec<Commitment<C>> = Vec::with_capacity(tu as usize);
    // first coefficient is the shared scalar
    cmm_sharing_coefficients.push(cmm_scalar);
    // randomness values corresponding to the commitments
    let mut cmm_coeff_randomness: Vec<PedersenRandomness<C>> = Vec::with_capacity(tu as usize);
    // first randomness is the one used in commiting to the scalar
    cmm_coeff_randomness.push(cmm_scalar_rand);
    // fill the rest
    for i in 1..tu {
        let (cmm, rnd) =
            commitment_key.commit(&sharing_data.coefficients[i as usize - 1], &mut csprng);
        cmm_sharing_coefficients.push(cmm);
        cmm_coeff_randomness.push(rnd);
    }
    // a vector of Ar data
    let mut ar_data: Vec<SingleArData<C>> = Vec::with_capacity(n as usize);
    for (i, (share_number, share)) in izip!(1..=n, sharing_data.shares.into_iter()) {
        let si = ShareNumber::from(i as u32);
        let ar = &ar_parameters.0[i as usize - 1];
        let pk = ar.ar_public_key;
        assert_eq!(ShareNumber::from(i), share_number);
        // encrypt the share
        let (cipher, rnd2) = pk.encrypt_exponent_rand(&mut csprng, &share);
        // compute the commitment to this share from the commitment to the coeff
        let (cmm, rnd) = commitment_to_share(si, &cmm_sharing_coefficients, &cmm_coeff_randomness);
        // fill Ar data
        let single_ar_data = SingleArData {
            ar_identity: ar.ar_identity,
            share,
            share_number: si,
            encrypted_share: cipher,
            encryption_randomness: rnd2,
            cmm_to_share: cmm,
            randomness_cmm_to_share: rnd,
            ar_public_key: pk,
        };
        ar_data.push(single_ar_data)
    }
    (ar_data, cmm_sharing_coefficients, cmm_coeff_randomness)
}

/// computing the commitment to single share from the commitments to
/// the coefficients of the polynomial
pub fn commitment_to_share<C: Curve>(
    share_number: ShareNumber,
    coeff_commitments: &[Commitment<C>],
    coeff_randomness: &[PedersenRandomness<C>],
) -> (Commitment<C>, PedersenRandomness<C>) {
    assert_eq!(coeff_commitments.len(), coeff_randomness.len());
    let mut cmm_share_point: C = C::zero_point();
    let mut cmm_share_randomness_scalar: C::Scalar = Field::zero();
    let share_scalar = share_number.to_scalar::<C>();
    // Horner's scheme in the exponent
    for cmm in coeff_commitments.iter().rev() {
        cmm_share_point = cmm_share_point.mul_by_scalar(&share_scalar);
        cmm_share_point = cmm_share_point.plus_point(cmm);
    }
    // Horner's scheme
    for rand in coeff_randomness.iter().rev() {
        cmm_share_randomness_scalar.mul_assign(&share_scalar);
        cmm_share_randomness_scalar.add_assign(rand);
    }
    let cmm = Commitment(cmm_share_point);
    let rnd = PedersenRandomness {
        randomness: cmm_share_randomness_scalar,
    };
    (cmm, rnd)
}

/// generates a credential deployment info
#[allow(clippy::too_many_arguments)]
pub fn generate_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    ip_info: &IpInfo<P, C>,
    global_context: &GlobalContext<C>,
    id_object: &IdentityObject<P, C, AttributeType>,
    id_object_use_data: &IdObjectUseData<P, C>,
    cred_counter: u8,
    policy: &Policy<C, AttributeType>,
    acc_data: &AccountData,
) -> Fallible<CredDeploymentInfo<P, C, AttributeType>>
where
    AttributeType: Clone,
{
    let mut csprng = thread_rng();

    let ip_sig = &id_object.signature;
    let sig_retrieval_rand = &id_object_use_data.randomness;
    let aci = &id_object_use_data.aci;
    let prio = &id_object.pre_identity_object;
    let alist = &id_object.alist;

    let prf_key = aci.prf_key;
    let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
    let reg_id_exponent = match aci.prf_key.prf_exponent(cred_counter) {
        Ok(exp) => exp,
        Err(_) => bail!(
            "Cannot create CDI with this account number because K + {} = 0.",
            cred_counter
        ),
    };

    // RegId as well as Prf key commitments must be computed
    // with the same generators as in the commitment key.
    let reg_id = global_context
        .on_chain_commitment_key
        .hide(
            &Value::view_scalar(&reg_id_exponent),
            &PedersenRandomness::zero(),
        )
        .0;
    // adding the chosen ar list to the credential deployment info
    let ar_list = &prio.choice_ar_parameters.ar_identities;
    let mut choice_ars = Vec::with_capacity(ar_list.len());
    let ip_ar_parameters = &ip_info.ip_ars.ars.clone();
    for ar in ar_list.iter() {
        match ip_ar_parameters.iter().find(|&x| x.ar_identity == *ar) {
            None => bail!("AR handle {} not supported by the identity provider.", *ar),
            Some(ar_info) => choice_ars.push(ar_info.clone()),
        }
    }
    let choice_ar_parameters = (choice_ars, prio.choice_ar_parameters.threshold);
    // sharing data for id cred sec
    let (id_cred_data, cmm_id_cred_sec_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data(
        id_cred_sec.view(),
        &choice_ar_parameters,
        &global_context.on_chain_commitment_key,
    );
    let number_of_ars = prio.choice_ar_parameters.ar_identities.len();
    // filling ar data
    let mut ar_data: Vec<ChainArData<C>> = Vec::with_capacity(number_of_ars);
    for item in id_cred_data.iter() {
        ar_data.push(ChainArData {
            ar_identity: item.ar_identity,
            enc_id_cred_pub_share: item.encrypted_share,
            id_cred_pub_share_number: item.share_number,
        });
    }

    let ip_pub_key = &ip_info.ip_verify_key;

    // retrieve the signature on the underlying idcredsec + prf_key + attribute_list
    let retrieved_sig = ip_sig.retrieve(&sig_retrieval_rand);

    // and then we blind the signature to disassociate it from the message.
    // only the second part is used (as per the protocol)
    let (blinded_sig, blind_rand) = retrieved_sig.blind(&mut csprng);

    // We now compute commitments to all the items in the attribute list.
    // We use the on-chain pedersen commitment key.
    let (commitments, commitment_rands) = compute_commitments(
        &global_context.on_chain_commitment_key,
        &alist,
        &prf_key,
        cred_counter,
        &cmm_id_cred_sec_sharing_coeff,
        &cmm_coeff_randomness,
        &policy,
        &mut csprng,
    );

    let cred_account = match acc_data.existing {
        // we are deploying on a new account
        // take all the keys that
        Either::Left(threshold) => CredentialAccount::NewAccount(
            acc_data
                .keys
                .values()
                .map(|kp| VerifyKey::Ed25519VerifyKey(kp.public))
                .collect::<Vec<_>>(),
            threshold,
        ),
        Either::Right(addr) => CredentialAccount::ExistingAccount(addr),
    };

    // We have all the values now.
    // FIXME: With more uniform infrastructure we can avoid all the cloning here.
    let cred_values = CredentialDeploymentValues {
        reg_id,
        threshold: prio.choice_ar_parameters.threshold,
        ar_data,
        ip_identity: ip_info.ip_identity,
        policy: policy.clone(),
        cred_account,
    };

    // Compute the challenge prefix by hashing the values.
    let ro = RandomOracle::domain("credential").append(&cred_values);

    let mut pok_id_cred_pub = Vec::with_capacity(number_of_ars);
    for item in id_cred_data.iter() {
        match choice_ar_parameters
            .0
            .iter()
            .find(|&x| x.ar_identity == item.ar_identity)
        {
            None => bail!("Cannot find AR {}", item.ar_identity),
            Some(ar_info) => {
                let secret = com_enc_eq::ComEncEqSecret {
                    value: &item.share,
                    elgamal_rand: &item.encryption_randomness,
                    pedersen_rand: &item.randomness_cmm_to_share,
                };

                let proof = com_enc_eq::prove_com_enc_eq(
                    ro.split(),
                    &item.encrypted_share,
                    &item.cmm_to_share,
                    &ar_info.ar_public_key,
                    &global_context.on_chain_commitment_key,
                    &secret,
                    &mut csprng,
                );
                pok_id_cred_pub.push((item.share_number, proof));
            }
        }
    }
    // and then use it to generate all the proofs.

    // Proof that the registration id is computed correctly from the prf key K and
    // the cred_counter x. At the moment there is no proof that x is less than
    // max_account.

    let pok_reg_id = compute_pok_reg_id(
        ro.split(),
        &global_context.on_chain_commitment_key,
        prf_key,
        &commitments.cmm_prf,
        &commitment_rands.prf_rand,
        cred_counter,
        &commitments.cmm_cred_counter,
        &commitment_rands.cred_counter_rand,
        reg_id_exponent,
        reg_id,
        &mut csprng,
    );

    let choice_ar_handles: Vec<ArIdentity> =
        cred_values.ar_data.iter().map(|x| x.ar_identity).collect();
    // Proof of knowledge of the signature of the identity provider.
    let pok_sig = compute_pok_sig(
        ro.split(),
        &global_context.on_chain_commitment_key,
        &commitments,
        &commitment_rands,
        &id_cred_sec,
        &prf_key,
        &alist,
        choice_ar_parameters.1,
        &choice_ar_handles,
        &ip_pub_key,
        &blinded_sig,
        &blind_rand,
        &mut csprng,
    )?;

    // Proof of knowledge of the secret keys of the account.
    // TODO: This might be replaced by just signatures.
    // What we do now is take all the keys in acc_data and provide a proof of
    // knowledge of the key.
    let proof_acc_sk = AccountOwnershipProof {
        proofs: acc_data
            .keys
            .iter()
            .map(|(&idx, kp)| {
                (
                    idx,
                    eddsa_dlog::prove_dlog_ed25519(ro.split(), &kp.public, &kp.secret),
                )
            })
            .collect(),
    };
    let cdp = CredDeploymentProofs {
        sig: blinded_sig,
        commitments,
        proof_id_cred_pub: pok_id_cred_pub,
        proof_ip_sig: pok_sig,
        proof_reg_id: pok_reg_id,
        proof_acc_sk,
    };

    let info = CredDeploymentInfo {
        values: cred_values,
        proofs: cdp,
    };
    Ok(info)
}

#[allow(clippy::too_many_arguments)]
fn compute_pok_sig<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
    R: Rng,
>(
    ro: RandomOracle,
    commitment_key: &PedersenKey<C>,
    commitments: &CredDeploymentCommitments<C>,
    commitment_rands: &CommitmentsRandomness<C>,
    id_cred_sec: &Value<C>,
    prf_key: &prf::SecretKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    threshold: Threshold,
    ar_list: &[ArIdentity],
    ip_pub_key: &ps_sig::PublicKey<P>,
    blinded_sig: &ps_sig::BlindedSignature<P>,
    blind_rand: &ps_sig::BlindingRandomness<P>,
    csprng: &mut R,
) -> Fallible<com_eq_sig::ComEqSigProof<P, C>> {
    let att_vec = &alist.alist;
    // number of user chosen attributes (+3 is for tags, valid_to and created_at)
    let num_user_attributes = att_vec.len() + 3;
    // To these there are always two attributes (idCredSec and prf key) added.
    let num_total_attributes = num_user_attributes + 2;
    let num_ars = ar_list.len(); // we commit to each anonymity revoker, with randomness 0
                                 // and finally we also commit to the anonymity revocation threshold.
                                 // so the total number of commitments is as follows
    let num_total_commitments = num_total_attributes + num_ars + 1;

    let y_tildas = &ip_pub_key.y_tildas;
    // FIXME: Handle errors more gracefully, or explicitly state precondition.
    ensure!(
        y_tildas.len() >= num_total_attributes,
        "Too many attributes."
    );

    let mut gxs = Vec::with_capacity(num_total_commitments);

    let mut secrets = Vec::with_capacity(num_total_commitments);
    secrets.push((
        Value {
            // FIXME: This should not be done! Breaks abstraction barrier.
            value: id_cred_sec.value,
        },
        commitment_rands.id_cred_sec_rand,
    ));
    gxs.push(y_tildas[0]);
    let prf_key_scalar = prf_key.0;
    secrets.push((
        Value {
            // FIXME: This should not be done! Breaks abstraction barrier.
            value: prf_key_scalar,
        },
        &commitment_rands.prf_rand,
    ));
    gxs.push(y_tildas[1]);
    // commitment randomness (0) for the threshold
    let zero = PedersenRandomness::zero();
    secrets.push((Value::new(threshold.to_scalar::<C>()), &zero));
    gxs.push(y_tildas[2]);
    for i in 3..num_ars + 3 {
        // all id revoker ids are commited with randomness 0
        secrets.push((Value::new(ar_list[i - 3].to_scalar::<C>()), &zero));
        gxs.push(y_tildas[i]);
    }

    let att_rands = &commitment_rands.attributes_rand;

    let tags_val = Value::new(encode_tags(alist.alist.keys())?);
    let tags_cmm = commitment_key.hide(&tags_val, &zero);

    let valid_to_val = Value::new(C::scalar_from_u64(alist.valid_to.into()));
    let valid_to_cmm = commitment_key.hide(&valid_to_val, &zero);

    let created_at_val = Value::new(C::scalar_from_u64(alist.created_at.into()));
    let created_at_cmm = commitment_key.hide(&created_at_val, &zero);

    secrets.push((tags_val, &zero));
    gxs.push(y_tildas[num_ars + 3]);
    secrets.push((valid_to_val, &zero));
    gxs.push(y_tildas[num_ars + 4]);
    secrets.push((created_at_val, &zero));
    gxs.push(y_tildas[num_ars + 5]);

    // FIXME: Likely we need to make sure there are enough y_tildas first and fail
    // gracefully otherwise.
    // NB: It is crucial here that we use a btreemap. This guarantees that
    // the att_vec.iter() iterator is ordered by keys.
    ensure!(
        y_tildas.len() > att_vec.len() + num_ars + 4,
        "The PS key must be long enough to accommodate all the attributes"
    );
    for (&g, (tag, v)) in y_tildas.iter().skip(num_ars + 4 + 1).zip(att_vec.iter()) {
        secrets.push((
            Value {
                value: v.to_field_element(),
            },
            // if we commited with non-zero randomness get it.
            // otherwise we must have commited with zero randomness
            // which we should use
            &att_rands.get(tag).unwrap_or(&zero),
        ));
        gxs.push(g);
    }

    let mut comm_vec = Vec::with_capacity(num_total_commitments);
    let cmm_id_cred_sec = commitments.cmm_id_cred_sec_sharing_coeff[0];
    comm_vec.push(cmm_id_cred_sec);
    comm_vec.push(commitments.cmm_prf);

    // add commitment to threshold with randomness 0
    comm_vec.push(commitment_key.hide(&Value::new(threshold.to_scalar::<C>()), &zero));

    // and all commitments to ARs with randomness 0
    for ar in ar_list.iter() {
        comm_vec.push(commitment_key.hide(&Value::new(ar.to_scalar::<C>()), &zero));
    }

    comm_vec.push(tags_cmm);
    comm_vec.push(valid_to_cmm);
    comm_vec.push(created_at_cmm);

    for (idx, v) in alist.alist.iter() {
        match commitments.cmm_attributes.get(idx) {
            None => {
                // need to commit with randomness 0
                let value = Value::new(v.to_field_element());
                let cmm = commitment_key.hide(&value, &zero);
                comm_vec.push(cmm);
            }
            Some(cmm) => comm_vec.push(*cmm),
        }
    }

    let secret = com_eq_sig::ComEqSigSecret {
        blind_rand,
        values_and_rands: &secrets,
    };
    let proof = com_eq_sig::prove_com_eq_sig::<P, C, R>(
        ro,
        blinded_sig,
        &comm_vec,
        ip_pub_key,
        commitment_key,
        &secret,
        csprng,
    );
    Ok(proof)
}

pub struct CommitmentsRandomness<'a, C: Curve> {
    id_cred_sec_rand: &'a PedersenRandomness<C>,
    prf_rand: PedersenRandomness<C>,
    cred_counter_rand: PedersenRandomness<C>,
    attributes_rand: HashMap<AttributeTag, PedersenRandomness<C>>,
}

/// Computing the commitments for the credential deployment info. We only
/// compute commitments for values that are not revealed as part of the policy.
/// For the other values the verifier (the chain) will compute commitments with
/// randomness 0 in order to verify knowledge of the signature.
#[allow(clippy::too_many_arguments)]
fn compute_commitments<'a, C: Curve, AttributeType: Attribute<C::Scalar>, R: Rng>(
    commitment_key: &PedersenKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    prf_key: &prf::SecretKey<C>,
    cred_counter: u8,
    cmm_id_cred_sec_sharing_coeff: &[Commitment<C>],
    cmm_coeff_randomness: &'a [PedersenRandomness<C>],
    policy: &Policy<C, AttributeType>,
    csprng: &mut R,
) -> (CredDeploymentCommitments<C>, CommitmentsRandomness<'a, C>) {
    let id_cred_sec_rand = &cmm_coeff_randomness[0];
    let prf::SecretKey(prf_scalar) = prf_key;
    let (cmm_prf, prf_rand) = commitment_key.commit(Value::view_scalar(prf_scalar), csprng);

    let cred_counter_scalar = C::scalar_from_u64(u64::from(cred_counter));
    let (cmm_cred_counter, cred_counter_rand) =
        commitment_key.commit(&Value::view_scalar(&cred_counter_scalar), csprng);
    let att_vec = &alist.alist;
    let n = att_vec.len();
    // only commitments to attributes which are not revealed.
    assert!(n >= policy.policy_vec.len());
    let cmm_len = n - policy.policy_vec.len();
    let mut cmm_attributes = BTreeMap::new();
    let mut attributes_rand = HashMap::with_capacity(cmm_len);
    for (&i, val) in att_vec.iter() {
        // in case the value is openened there is no need to hide it.
        // We can just commit with randomness 0.
        if !policy.policy_vec.contains_key(&i) {
            let value = Value::new(val.to_field_element());
            let (cmm, rand) = commitment_key.commit(&value, csprng);
            cmm_attributes.insert(i, cmm);
            attributes_rand.insert(i, rand);
        }
    }
    let cdc = CredDeploymentCommitments {
        cmm_prf,
        cmm_cred_counter,
        cmm_attributes,
        cmm_id_cred_sec_sharing_coeff: cmm_id_cred_sec_sharing_coeff.to_owned(),
    };

    let cr = CommitmentsRandomness {
        id_cred_sec_rand,
        prf_rand,
        cred_counter_rand,
        attributes_rand,
    };
    (cdc, cr)
}

/// proof of knowledge of registration id
#[allow(clippy::too_many_arguments)]
fn compute_pok_reg_id<C: Curve, R: Rng>(
    ro: RandomOracle,
    on_chain_commitment_key: &PedersenKey<C>,
    prf_key: prf::SecretKey<C>,
    cmm_prf: &Commitment<C>,
    prf_rand: &PedersenRandomness<C>,
    cred_counter: u8,
    cmm_cred_counter: &Commitment<C>,
    cred_counter_rand: &PedersenRandomness<C>,
    reg_id_exponent: C::Scalar,
    reg_id: C,
    csprng: &mut R,
) -> com_mult::ComMultProof<C> {
    // Commitment to 1 with randomness 0, to serve as the right-hand side in
    // com_mult proof.
    // NOTE: In order for this to work the reg_id must be computed
    // with the same base as the first element of the commitment key.
    let cmm_one = on_chain_commitment_key.hide(
        &Value::view_scalar(&C::Scalar::one()),
        &PedersenRandomness::zero(),
    );

    // commitments are the public values. They all have to
    let public = [
        cmm_prf.combine(&cmm_cred_counter),
        Commitment(reg_id),
        cmm_one,
    ];
    // finally the secret keys are derived from actual commited values
    // and the randomness.

    let mut k = prf_key.0;
    // FIXME: Handle the error case (which cannot happen for the current curve, but
    // in general ...)
    k.add_assign(&C::scalar_from_u64(u64::from(cred_counter)));
    let mut rand_1 = prf_rand.randomness;
    rand_1.add_assign(&cred_counter_rand);
    // reg_id is the commitment to reg_id_exponent with randomness 0
    // the right-hand side of the equation is commitment to 1 with randomness 0
    let values = [
        Value::new(k),
        Value::new(reg_id_exponent),
        Value::new(C::Scalar::one()),
    ];
    let rands = [
        PedersenRandomness { randomness: rand_1 },
        PedersenRandomness::zero(),
        PedersenRandomness::zero(),
    ];

    let secret = com_mult::ComMultSecret {
        values: &values,
        rands: &rands,
    };

    com_mult::prove_com_mult(
        ro,
        &public[0],
        &public[1],
        &public[2],
        on_chain_commitment_key,
        &secret,
        csprng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{ffi::*, identity_provider::*, secret_sharing::Threshold, test::*};

    use curve_arithmetic::Curve;
    use ed25519_dalek as ed25519;
    use either::Left;
    use std::convert::TryFrom;

    use pedersen_scheme::key::CommitmentKey as PedersenKey;

    type ExampleCurve = pairing::bls12_381::G1;

    /// Construct PIO, test various proofs are valid
    #[test]
    pub fn test_pio_correctness() {
        let mut csprng = thread_rng();

        // Create IP info
        let max_attrs = 10;
        let num_ars = 4;
        let (
            IpData {
                public_ip_info: ip_info,
                ip_secret_key: _,
                metadata: _,
            },
            _,
        ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let aci = test_create_aci(&mut csprng);
        let (context, pio, _) = test_create_pio(&aci, &ip_info, num_ars);

        // Check id_cred_pub is correct
        let id_cred_sec = aci.cred_holder_info.id_cred.id_cred_sec.value;
        let id_cred_pub = ip_info.ip_ars.ar_base.mul_by_scalar(&id_cred_sec);
        assert_eq!(pio.id_cred_pub, id_cred_pub);

        // Check proof_com_eq_sc is valid
        let sc_ck = PedersenKey(
            context.ip_info.ip_verify_key.ys[0],
            context.ip_info.ip_verify_key.g,
        );
        let proof_com_eq_sc_valid = com_eq::verify_com_eq_single(
            RandomOracle::empty(),
            &pio.cmm_sc,
            &pio.id_cred_pub,
            &sc_ck,
            &ip_info.ip_ars.ar_base,
            &pio.proof_com_eq_sc,
        );
        assert!(proof_com_eq_sc_valid, "proof_com_eq_sc is not valid");

        // Check ip_ar_data is valid (could use more checks)
        assert_eq!(
            pio.ip_ar_data.len() as u8,
            num_ars - 1,
            "ip_ar_data has wrong length"
        );

        // Check pok_sc is valid
        let pok_sc_valid = dlog::verify_dlog(
            RandomOracle::empty(),
            &ip_info.ip_ars.ar_base,
            &id_cred_pub,
            &pio.pok_sc,
        );
        assert!(pok_sc_valid, "proof_sc is not valid");

        // Check proof_com_eq is valid
        let commitment_key_prf = PedersenKey(
            context.ip_info.ip_verify_key.ys[1],
            context.ip_info.ip_verify_key.g,
        );
        let proof_com_eq_valid = com_eq_different_groups::verify_com_eq_diff_grps(
            RandomOracle::empty(),
            &pio.cmm_prf,
            &pio.cmm_prf_sharing_coeff[0],
            &commitment_key_prf,
            &context.ip_info.ip_ars.ar_cmm_key,
            &pio.proof_com_eq,
        );
        assert!(proof_com_eq_valid, "proof_com_eq is not valid");
    }

    #[test]
    pub fn test_compute_sharing_data() {
        use curve_arithmetic::secret_value::Value;

        let mut csprng = thread_rng();

        // Arrange
        let num_ars = 4;
        let threshold = 3;
        let ar_base = ExampleCurve::generate(&mut csprng);
        let (ar_infos, _ar_keys) = test_create_ars(&ar_base, num_ars, &mut csprng);
        let ar_parameters = (ar_infos, Threshold(threshold));
        let ck = PedersenKey::generate(&mut csprng);
        let value = Value::<ExampleCurve>::generate(&mut csprng);

        // Act
        let (ar_datas, _comms, _rands) = compute_sharing_data(&value, &ar_parameters, &ck);

        // Assert ArData's are good
        for (i, data) in ar_datas.iter().enumerate() {
            assert_eq!(
                data.ar_identity,
                (ar_parameters.0)[i].ar_identity,
                "ArData ar_identity is invalid"
            );
            assert_eq!(
                data.share_number,
                ShareNumber(i as u32 + 1),
                "ArData share_number is invalid"
            );
            // Add check of encrypted_share and encrypted_randomness
            let cmm_ok = ck.open(
                &data.share,
                &data.randomness_cmm_to_share,
                &data.cmm_to_share,
            );
            assert!(cmm_ok, "ArData cmm_to_share is not valid");
            assert_eq!(
                data.ar_public_key, data.ar_public_key,
                "ArData ar_public_key is invalid"
            );
        }

        // Add check of commitment to polynomial coefficients and randomness
        // encodes value
    }

    /// This test generates a CDI and check values were set correct.
    /// It does not yet test the proofs for correct-/soundness.
    #[test]
    pub fn test_generate_cdi() {
        // Create IP info with threshold = num_ars - 1
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (
            IpData {
                public_ip_info: ip_info,
                ip_secret_key,
                metadata: _,
            },
            _,
        ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let aci = test_create_aci(&mut csprng);
        let (_context, pio, randomness) = test_create_pio(&aci, &ip_info, num_ars);
        let alist = test_create_attributes();
        let sig_ok = verify_credentials(&pio, &ip_info, &alist, &ip_secret_key);
        let ip_sig = sig_ok.unwrap();

        // Create CDI arguments
        let global_ctx = GlobalContext {
            on_chain_commitment_key: PedersenKey::generate(&mut csprng),
        };
        let id_object = IdentityObject {
            pre_identity_object: pio,
            alist,
            signature: ip_sig,
        };
        let id_use_data = IdObjectUseData { aci, randomness };
        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
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
        keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));
        let sigthres = SignatureThreshold(2);
        let acc_data = AccountData {
            keys,
            existing: Left(sigthres),
        };

        let cred_ctr = 42;
        let cdi = generate_cdi(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_use_data,
            cred_ctr,
            &policy,
            &acc_data,
        )
        .expect("Could not generate CDI");

        // Check cred_account
        let cred_account_ok = match cdi.values.cred_account {
            CredentialAccount::NewAccount(k, t) if k.len() == 3 && t == sigthres => true,
            _ => false,
        };
        assert!(cred_account_ok, "CDI cred_account is invalid");

        // Check reg_id
        let reg_id_exponent = id_use_data.aci.prf_key.prf_exponent(cred_ctr).unwrap();
        let reg_id = global_ctx
            .on_chain_commitment_key
            .hide(
                &Value::view_scalar(&reg_id_exponent),
                &PedersenRandomness::zero(),
            )
            .0;
        assert_eq!(cdi.values.reg_id, reg_id, "CDI reg_id is invalid");

        // Check ip_identity
        assert_eq!(
            cdi.values.ip_identity, ip_info.ip_identity,
            "CDI ip_identity is invalid"
        );

        // Check threshold
        assert_eq!(
            cdi.values.threshold,
            Threshold(num_ars as u32 - 1),
            "CDI threshold is invalid"
        );

        // Check ar_data
        assert_eq!(
            cdi.values.ar_data.len() as u8,
            num_ars - 1,
            "CDI ar_data length is invalid"
        );

        // Check policy
        assert_eq!(cdi.values.policy, policy, "CDI policy is invalid");

        // Add checks for proofs
    }
}
