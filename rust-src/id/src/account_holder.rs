use crate::{types::*, utils};

use failure::Fallible;

use random_oracle::RandomOracle;

use crate::{
    secret_sharing::*,
    sigma_protocols::{
        com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult, common::*, dlog,
    },
};
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use either::Either;
use elgamal::cipher::Cipher;
use ff::Field;
use pedersen_scheme::{
    commitment::Commitment, key::CommitmentKey as PedersenKey,
    randomness::Randomness as PedersenRandomness, value::Value,
};
use rand::*;
use std::collections::{btree_map::BTreeMap, hash_map::HashMap};

/// Generate PreIdentityObject out of the account holder information,
/// the chosen anonymity revoker information, and the necessary contextual
/// information (group generators, shared commitment keys, etc).
pub fn generate_pio<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    context: &Context<P, C>,
    aci: &AccCredentialInfo<C>,
) -> Option<(PreIdentityObject<P, C>, ps_sig::SigRetrievalRandomness<P>)> {
    let mut csprng = thread_rng();
    let id_cred_pub = context
        .ip_info
        .ip_ars
        .ar_base
        .mul_by_scalar(&aci.cred_holder_info.id_cred.id_cred_sec);

    // PRF related computation
    let prf_key = &aci.prf_key;
    // FIXME: The next item will change to encrypt by chunks to enable anonymity
    // revocation.
    // sharing data, commitments to sharing coefficients, and randomness of the
    // commitments sharing data is a list of SingleArData
    let prf_value = aci.prf_key.to_value();

    let (prf_key_data, cmm_prf_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data(
        &prf_value,
        &context.choice_ar_parameters,
        &context.ip_info.ip_ars.ar_cmm_key,
    );
    let number_of_ars = context.choice_ar_parameters.0.len();
    let mut ip_ar_data = Vec::with_capacity(number_of_ars);
    let ar_commitment_key = context.ip_info.ip_ars.ar_cmm_key;

    // Commit and prove knowledge of id_cred_sec
    let id_cred_sec = &aci.cred_holder_info.id_cred.id_cred_sec;
    let sc_ck = PedersenKey(
        context.ip_info.ip_verify_key.ys[0],
        context.ip_info.ip_verify_key.g,
    );

    let (cmm_sc, cmm_sc_rand) = sc_ck.commit(&id_cred_sec, &mut csprng);
    let cmm_sc_rand = cmm_sc_rand;
    // We now construct all the zero-knowledge proofs.
    // Since all proofs must be bound together, we
    // first construct inputs to all the proofs, and only at the end
    // do we produce all the different witnesses.

    // First the proof that we know id_cred_sec.
    let prover = dlog::Dlog::<C> {
        public: id_cred_pub,
        coeff:  context.ip_info.ip_ars.ar_base,
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
            g:          context.ip_info.ip_ars.ar_base,
        },
    };
    let secret = (secret, com_eq::ComEqSecret::<P::G1> {
        r: cmm_sc_rand.clone(),
        a: id_cred_sec.view(),
    });

    // Commit to the PRF key for the IP and prove equality for the secret-shared PRF
    // key
    let commitment_key_prf = PedersenKey(
        context.ip_info.ip_verify_key.ys[1],
        context.ip_info.ip_verify_key.g,
    );
    let (cmm_prf, rand_cmm_prf) = commitment_key_prf.commit(prf_key, &mut csprng);
    let rand_cmm_prf = rand_cmm_prf;
    let snd_cmm_prf = cmm_prf_sharing_coeff.first()?;
    let rand_snd_cmm_prf = cmm_coeff_randomness.first()?.clone();

    // Next the proof that the two commitments to the prf key are the same.
    let prover = prover.add_prover(com_eq_different_groups::ComEqDiffGroups {
        commitment_1: cmm_prf,
        commitment_2: *snd_cmm_prf,
        cmm_key_1:    commitment_key_prf,
        cmm_key_2:    context.ip_info.ip_ars.ar_cmm_key,
    });
    let secret = (secret, com_eq_different_groups::ComEqDiffGroupsSecret {
        value:      prf_key.to_value(),
        rand_cmm_1: rand_cmm_prf.clone(),
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

    for item in prf_key_data.iter() {
        let secret = com_enc_eq::ComEncEqSecret {
            value:         item.share.clone(),
            elgamal_rand:  item.encryption_randomness.clone(),
            pedersen_rand: item.randomness_cmm_to_share.clone(),
        };
        // FIXME: Need some context in the challenge computation.
        let item_prover = com_enc_eq::ComEncEq {
            cipher:     item.encrypted_share,
            commitment: item.cmm_to_share,
            pub_key:    item.ar_public_key,
            cmm_key:    ar_commitment_key,
        };
        replicated_provers.push(item_prover);
        replicated_secrets.push(secret);
        ip_ar_data.push((item.ar_identity, move |proof_com_enc_eq| IpArData {
            enc_prf_key_share: item.encrypted_share,
            proof_com_enc_eq,
        }));
    }

    // Extract identities of the chosen ARs for use in PIO
    let ar_identities = context
        .choice_ar_parameters
        .0
        .iter()
        .map(|x| x.ar_identity)
        .collect();

    let threshold = context.choice_ar_parameters.1;

    let prover = prover.add_prover(ReplicateAdapter {
        protocols: replicated_provers,
    });

    let secret = (secret, replicated_secrets);

    let proof = prove(RandomOracle::empty(), &prover, secret, &mut csprng)?;

    let ip_ar_data = ip_ar_data
        .iter()
        .zip(proof.witness.w2.witnesses.into_iter())
        .map(|(&(ar_id, f), w)| (ar_id, f(w)))
        .collect::<BTreeMap<ArIdentity, _>>();
    let poks = PreIdentityProof {
        challenge:              proof.challenge,
        id_cred_sec_witness:    proof.witness.w1.w1.w1,
        commitments_same_proof: proof.witness.w1.w1.w2,
        commitments_prf_same:   proof.witness.w1.w2,
    };
    // attribute list
    let prio = PreIdentityObject {
        id_cred_pub,
        ip_ar_data,
        choice_ar_parameters: ChoiceArParameters {
            ar_identities,
            threshold,
        },
        cmm_sc,
        cmm_prf,
        cmm_prf_sharing_coeff,
        poks,
    };

    // randomness to retrieve the signature
    // We add randomness from both of the commitments.
    // See specification of ps_sig and id layer for why this is so.
    let mut sig_retrieval_rand = P::ScalarField::zero();
    sig_retrieval_rand.add_assign(&cmm_sc_rand);
    sig_retrieval_rand.add_assign(&rand_cmm_prf);
    Some((
        prio,
        ps_sig::SigRetrievalRandomness::new(sig_retrieval_rand),
    ))
}

/// Convenient data structure to collect data related to a single AR
pub struct SingleArData<C: Curve> {
    ar_identity:             ArIdentity,
    share:                   Value<C>,
    encrypted_share:         Cipher<C>,
    encryption_randomness:   elgamal::Randomness<C>,
    cmm_to_share:            Commitment<C>,
    randomness_cmm_to_share: PedersenRandomness<C>,
    ar_public_key:           elgamal::PublicKey<C>,
}

type SharingData<C> = (
    Vec<SingleArData<C>>,
    Vec<Commitment<C>>, /* Commitments to the coefficients of sharing polynomial S + b1 X + b2
                         * X^2... */
    Vec<PedersenRandomness<C>>,
);

/// A function to compute sharing data for a single value.
pub fn compute_sharing_data<C: Curve>(
    shared_scalar: &Value<C>,                    // Value to be shared.
    ar_parameters: &(Vec<ArInfo<C>>, Threshold), // Anonimity revokers
    commitment_key: &PedersenKey<C>,             // commitment key
) -> SharingData<C> {
    let n = ar_parameters.0.len() as u32;
    let t = ar_parameters.1;
    let mut csprng = thread_rng();
    // first commit to the scalar
    let (cmm_scalar, cmm_scalar_rand) = commitment_key.commit(&shared_scalar, &mut csprng);
    // We evaluate the polynomial at ar_identities.
    let share_points = ar_parameters.0.iter().map(|x| x.ar_identity);
    // share the scalar on ar_identity points.
    let sharing_data = share::<C, _, _, _>(&shared_scalar, share_points, t, &mut csprng);
    // commitments to the sharing coefficients
    let mut cmm_sharing_coefficients: Vec<Commitment<C>> = Vec::with_capacity(t.into());
    // first coefficient is the shared scalar
    cmm_sharing_coefficients.push(cmm_scalar);
    // randomness values corresponding to the commitments
    let mut cmm_coeff_randomness = Vec::with_capacity(t.into());
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
    for (ar, share) in izip!(ar_parameters.0.iter(), sharing_data.shares.into_iter()) {
        let si = ar.ar_identity;
        let pk = ar.ar_public_key;
        // encrypt the share
        let (cipher, rnd2) = pk.encrypt_exponent_rand(&mut csprng, &share);
        // compute the commitment to this share from the commitment to the coeff
        let (cmm, rnd) =
            commitment_to_share_and_rand(si, &cmm_sharing_coefficients, &cmm_coeff_randomness);
        // fill Ar data
        let single_ar_data = SingleArData {
            ar_identity: si,
            share,
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

/// Generates a credential deployment info.
/// The information is meant to be valid in the context of a given identity
/// provider, and global parameter.
/// The 'cred_counter' is used to generate a new credential ID.
pub fn create_credential<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    ip_info: &IpInfo<P, C>,
    global_context: &GlobalContext<C>,
    id_object: &IdentityObject<P, C, AttributeType>,
    id_object_use_data: &IdObjectUseData<P, C>,
    cred_counter: u8,
    policy: Policy<C, AttributeType>,
    acc_data: &AccountData,
) -> Fallible<CredDeploymentInfo<P, C, AttributeType>>
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();

    let ip_sig = &id_object.signature;
    let sig_retrieval_rand = &id_object_use_data.randomness;
    let aci = &id_object_use_data.aci;
    let prio = &id_object.pre_identity_object;
    let alist = &id_object.alist;

    let prf_key = &aci.prf_key;
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
            &Value::<C>::new(reg_id_exponent),
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
        id_cred_sec,
        &choice_ar_parameters,
        &global_context.on_chain_commitment_key,
    );
    let number_of_ars = prio.choice_ar_parameters.ar_identities.len();
    // filling ar data
    let mut ar_data = BTreeMap::new();
    for item in id_cred_data.iter() {
        if ar_data
            .insert(item.ar_identity, ChainArData {
                enc_id_cred_pub_share: item.encrypted_share,
            })
            .is_some()
        {
            bail!("Duplicate identity providers.")
        }
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
        prf_key,
        cred_counter,
        &cmm_id_cred_sec_sharing_coeff,
        cmm_coeff_randomness,
        &policy,
        &mut csprng,
    )?;

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
    let cred_values = CredentialDeploymentValues {
        reg_id,
        threshold: prio.choice_ar_parameters.threshold,
        ar_data,
        ip_identity: ip_info.ip_identity,
        policy,
        cred_account,
    };

    // We now produce all the proofs.
    // Compute the challenge prefix by hashing the values.
    // FIXME: We should do something different here.
    // Eventually we'll have to include the genesis hash.
    let ro = RandomOracle::domain("credential").append(&cred_values);

    let mut id_cred_pub_share_numbers = Vec::with_capacity(number_of_ars);
    let mut id_cred_pub_provers = Vec::with_capacity(number_of_ars);
    let mut id_cred_pub_secrets = Vec::with_capacity(number_of_ars);

    for item in id_cred_data.iter() {
        match choice_ar_parameters
            .0
            .iter()
            .find(|&x| x.ar_identity == item.ar_identity)
        {
            None => bail!("Cannot find AR {}", item.ar_identity),
            Some(ar_info) => {
                let secret = com_enc_eq::ComEncEqSecret {
                    value:         item.share.clone(),
                    elgamal_rand:  item.encryption_randomness.clone(),
                    pedersen_rand: item.randomness_cmm_to_share.clone(),
                };

                let item_prover = com_enc_eq::ComEncEq {
                    cipher:     item.encrypted_share,
                    commitment: item.cmm_to_share,
                    pub_key:    ar_info.ar_public_key,
                    cmm_key:    global_context.on_chain_commitment_key,
                };

                id_cred_pub_share_numbers.push(ar_info.ar_identity);
                id_cred_pub_provers.push(item_prover);
                id_cred_pub_secrets.push(secret);
            }
        }
    }

    // Proof that the registration id is computed correctly from the prf key K and
    // the cred_counter x. At the moment there is no proof that x is less than
    // max_account.
    let (prover_reg_id, secret_reg_id) = compute_pok_reg_id(
        &global_context.on_chain_commitment_key,
        prf_key.clone(),
        &commitments.cmm_prf,
        &commitment_rands.prf_rand,
        cred_counter,
        &commitments.cmm_cred_counter,
        &commitment_rands.cred_counter_rand,
        &commitment_rands.max_accounts_rand,
        reg_id_exponent,
        reg_id,
    );

    let choice_ar_handles: Vec<ArIdentity> = cred_values.ar_data.iter().map(|(x, _)| *x).collect();

    // Proof of knowledge of the signature of the identity provider.
    let (prover_sig, secret_sig) = compute_pok_sig(
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
    // FIXME: Pass in a mutable random-oracle so it can be extended.
    let proof = match prove(ro.split(), &prover, secret, &mut csprng) {
        Some(x) => x,
        None => bail!("Cannot produce zero knowledge proof."),
    };

    // Proof of knowledge of the secret keys of the account.
    // TODO: This might be replaced by just signatures.
    // What we do now is take all the keys in acc_data and provide a proof of
    // knowledge of the key.
    // FIXME: This should be integrated into the other proofs.
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
        challenge: proof.challenge,
        proof_id_cred_pub: id_cred_pub_share_numbers
            .into_iter()
            .zip(proof.witness.w2.witnesses)
            .collect(),
        proof_reg_id: proof.witness.w1.w1,
        proof_ip_sig: proof.witness.w1.w2,
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
>(
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
    blind_rand: ps_sig::BlindingRandomness<P>,
) -> Fallible<(com_eq_sig::ComEqSig<P, C>, com_eq_sig::ComEqSigSecret<P, C>)> {
    let att_vec = &alist.alist;
    // number of user chosen attributes (+4 is for tags, valid_to, created_at,
    // max_accounts)
    let num_user_attributes = att_vec.len() + 4;
    // To these there are always two attributes (idCredSec and prf key) added.
    let num_total_attributes = num_user_attributes + 2;
    let ar_scalars = match encode_ars(ar_list) {
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
    // commitment randomness (0) for the threshold
    let zero = PedersenRandomness::<C>::zero();
    secrets.push((Value::new(threshold.to_scalar::<C>()), zero.clone()));
    gxs.push(y_tildas[2]);
    for i in 3..num_ars + 3 {
        // the encoded id revoker are commited with randomness 0.
        secrets.push((Value::new(ar_scalars[i - 3]), zero.clone()));
        gxs.push(y_tildas[i]);
    }

    let att_rands = &commitment_rands.attributes_rand;

    let tags_val = Value::new(encode_tags(alist.alist.keys())?);
    let tags_cmm = commitment_key.hide(&tags_val, &zero);

    let valid_to_val = Value::new(C::scalar_from_u64(alist.valid_to.into()));
    let valid_to_cmm = commitment_key.hide(&valid_to_val, &zero);

    let created_at_val = Value::new(C::scalar_from_u64(alist.created_at.into()));
    let created_at_cmm = commitment_key.hide(&created_at_val, &zero);

    let max_accounts_val = Value::new(C::scalar_from_u64(alist.max_accounts.into()));
    let max_accounts_cmm =
        commitment_key.hide(&max_accounts_val, &commitment_rands.max_accounts_rand);

    secrets.push((tags_val, zero.clone()));
    gxs.push(y_tildas[num_ars + 3]);
    secrets.push((valid_to_val, zero.clone()));
    gxs.push(y_tildas[num_ars + 4]);
    secrets.push((created_at_val, zero.clone()));
    gxs.push(y_tildas[num_ars + 5]);
    secrets.push((max_accounts_val, commitment_rands.max_accounts_rand.clone()));
    gxs.push(y_tildas[num_ars + 6]);

    // NB: It is crucial here that we use a btreemap. This guarantees that
    // the att_vec.iter() iterator is ordered by keys.
    for (&g, (tag, v)) in y_tildas.iter().skip(num_ars + 5 + 1).zip(att_vec.iter()) {
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
    comm_vec.push(commitment_key.hide(&Value::<C>::new(threshold.to_scalar::<C>()), &zero));

    // and all commitments to ARs with randomness 0
    for ar in ar_scalars.iter() {
        comm_vec.push(commitment_key.hide_worker(&ar, &zero));
    }

    comm_vec.push(tags_cmm);
    comm_vec.push(valid_to_cmm);
    comm_vec.push(created_at_cmm);
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
        ps_pub_key: ip_pub_key.clone(),
        comm_key:   *commitment_key,
    };
    Ok((prover, secret))
}

pub struct CommitmentsRandomness<C: Curve> {
    id_cred_sec_rand:  PedersenRandomness<C>,
    prf_rand:          PedersenRandomness<C>,
    cred_counter_rand: PedersenRandomness<C>,
    max_accounts_rand: PedersenRandomness<C>,
    attributes_rand:   HashMap<AttributeTag, PedersenRandomness<C>>,
}

/// Computing the commitments for the credential deployment info. We only
/// compute commitments for values that are not revealed as part of the policy.
/// For the other values the verifier (the chain) will compute commitments with
/// randomness 0 in order to verify knowledge of the signature.
#[allow(clippy::too_many_arguments)]
fn compute_commitments<C: Curve, AttributeType: Attribute<C::Scalar>, R: Rng>(
    commitment_key: &PedersenKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    prf_key: &prf::SecretKey<C>,
    cred_counter: u8,
    cmm_id_cred_sec_sharing_coeff: &[Commitment<C>],
    cmm_coeff_randomness: Vec<PedersenRandomness<C>>,
    policy: &Policy<C, AttributeType>,
    csprng: &mut R,
) -> Fallible<(CredDeploymentCommitments<C>, CommitmentsRandomness<C>)> {
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
    assert!(n >= policy.policy_vec.len());
    let cmm_len = n - policy.policy_vec.len();
    let mut cmm_attributes = BTreeMap::new();
    let mut attributes_rand = HashMap::with_capacity(cmm_len);
    for (&i, val) in att_vec.iter() {
        // in case the value is openened there is no need to hide it.
        // We can just commit with randomness 0.
        if !policy.policy_vec.contains_key(&i) {
            let value = Value::<C>::new(val.to_field_element());
            let (cmm, rand) = commitment_key.commit(&value, csprng);
            cmm_attributes.insert(i, cmm);
            attributes_rand.insert(i, rand);
        }
    }
    let cdc = CredDeploymentCommitments {
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
        cmm_prf.combine(&cmm_cred_counter),
        Commitment(reg_id),
        cmm_one,
    ];
    // finally the secret keys are derived from actual commited values
    // and the randomness.

    let mut k = C::scalar_from_u64(u64::from(cred_counter));
    k.add_assign(&prf_key);

    // combine the two randomness witnesses
    let mut rand_1 = C::Scalar::zero();
    rand_1.add_assign(&prf_rand);
    rand_1.add_assign(&cred_counter_rand);
    // reg_id is the commitment to reg_id_exponent with randomness 0
    // the right-hand side of the equation is commitment to 1 with randomness 0
    let values = [
        Value::new(k),
        Value::new(reg_id_exponent),
        Value::new(C::Scalar::one()),
    ];
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{ffi::*, identity_provider::*, secret_sharing::Threshold, test::*};

    use curve_arithmetic::Curve;
    use ed25519_dalek as ed25519;
    use either::Left;

    use pedersen_scheme::key::CommitmentKey as PedersenKey;

    type ExampleCurve = pairing::bls12_381::G1;
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
    pub fn test_create_credential() {
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
        keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));
        let sigthres = SignatureThreshold(2);
        let acc_data = AccountData {
            keys,
            existing: Left(sigthres),
        };

        let cred_ctr = 42;
        let cdi = create_credential(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_use_data,
            cred_ctr,
            policy.clone(),
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
                &Value::<ExampleCurve>::new(reg_id_exponent),
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
            Threshold(num_ars - 1),
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
