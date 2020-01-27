use crate::types::*;

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
use rand::*;
use rand::rngs::ThreadRng;
use std::collections::{btree_map::BTreeMap, hash_map::HashMap};

/// Generate PreIdentityObject out of the account holder information,
/// the chosen anonymity revoker information, and the necessary contextual
/// information (group generators, shared commitment keys, etc).
pub fn generate_pio<
    P: Pairing,
    AttributeType: Attribute<C::Scalar>,
    C: Curve<Scalar = P::ScalarField>,
>(
    context: &Context<P, C>,
    aci: &AccCredentialInfo<C, AttributeType>,
) -> (
    PreIdentityObject<P, C, AttributeType>,
    ps_sig::SigRetrievalRandomness<P>,
)
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();
    let id_ah = aci.acc_holder_info.id_ah.clone();
    let id_cred_pub = context
        .ip_info
        .ar_base
        .mul_by_scalar(&aci.acc_holder_info.id_cred.id_cred_sec);
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
        &context.ip_info.ar_info.1,
    );
    let number_of_ars = context.choice_ar_parameters.0.len();
    let mut ip_ar_data: Vec<IpArData<C>> = Vec::with_capacity(number_of_ars);
    let ar_commitment_key = context.ip_info.ar_info.1;
    // filling IpArData
    // to shares
    for item in prf_key_data.iter() {
        let secret = com_enc_eq::ComEncEqSecret {
            value:         &item.share,
            elgamal_rand:  &item.encryption_randomness,
            pedersen_rand: &item.randomness_cmm_to_share,
        };

        // generating proofs that the encryptions of shares hides the same value as the
        // commitments
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
            ar_identity:          item.ar_identity,
            enc_prf_key_share:    item.encrypted_share,
            prf_key_share_number: item.share_number,
            proof_com_enc_eq:     proof,
        });
    }

    // id_cred_sec stuff
    let id_cred_sec = &aci.acc_holder_info.id_cred.id_cred_sec;
    let sc_ck = PedersenKey(
        context.ip_info.ip_verify_key.ys[0],
        context.ip_info.ip_verify_key.g,
    );
    // commit to id_cred_sec
    let (cmm_sc, cmm_sc_rand) = sc_ck.commit(id_cred_sec.view(), &mut csprng);
    // proof of knowledge of id_cred_sec
    // w.r.t. the commitment
    let pok_sc =
        // FIXME: prefix needs to be all the data sent to id provider or some such.
        dlog::prove_dlog(&mut csprng,
                         RandomOracle::empty(),
                         &id_cred_pub,
                         id_cred_sec,
                         &context.ip_info.ar_base
        );

    let ar_ck = context.ip_info.ar_info.1;
    let (snd_cmm_sc, snd_cmm_sc_rand) = ar_ck.commit(id_cred_sec.view(), &mut csprng);
    let snd_pok_sc = {
        // FIXME: prefix needs to be all the data sent to id provider or some such.
        com_eq::prove_com_eq(
            RandomOracle::empty(),
            &[snd_cmm_sc],
            &id_cred_pub,
            &ar_ck,
            &[context.ip_info.ar_base],
            &[(&snd_cmm_sc_rand, id_cred_sec.view())],
            &mut csprng,
        )
    };

    let proof_com_eq_sc = {
        // FIXME: prefix needs to be all the data sent to the id provider.
        com_eq::prove_com_eq_single(
            RandomOracle::empty(),
            &cmm_sc,
            &id_cred_pub,
            &sc_ck,
            &context.ip_info.ar_base,
            (&cmm_sc_rand, Value::<P::G1>::view_scalar(&id_cred_sec)),
            &mut csprng,
        )
    };

    // commitment to the prf key in the group of the IP
    let commitment_key_prf = PedersenKey(
        context.ip_info.ip_verify_key.ys[1],
        context.ip_info.ip_verify_key.g,
    );
    let (cmm_prf, rand_cmm_prf) =
        commitment_key_prf.commit(&pedersen::Value::view_scalar(&prf_key_scalar), &mut csprng);
    // commitment to the prf key in the group of the AR
    let snd_cmm_prf = &cmm_prf_sharing_coeff[0];
    let rand_snd_cmm_prf = &cmm_coeff_randomness[0];
    // now generate the proof that the commitment hidden in snd_cmm_prf is to
    // the same prf key as the one encrypted in id_ar_data via anonymity revokers
    // public key.
    let proof_com_eq = {
        let secret = com_eq_different_groups::ComEqDiffGrpsSecret {
            value:      Value::view_scalar(&prf_key_scalar),
            rand_cmm_1: &rand_cmm_prf,
            rand_cmm_2: rand_snd_cmm_prf,
        };
        com_eq_different_groups::prove_com_eq_diff_grps(
            RandomOracle::empty(),
            &cmm_prf,
            snd_cmm_prf,
            &commitment_key_prf,
            &context.ip_info.ar_info.1,
            &secret,
            &mut csprng,
        )
    };
    // identities of the chosen AR's
    let ar_handles = context
        .choice_ar_parameters
        .0
        .iter()
        .map(|x| x.ar_identity)
        .collect();
    let revocation_threshold = context.choice_ar_parameters.1;
    // attribute list
    let alist = aci.attributes.clone();
    let prio = PreIdentityObject {
        id_ah,
        id_cred_pub,
        snd_pok_sc,
        proof_com_eq_sc,
        ip_ar_data,
        choice_ar_parameters: (ar_handles, revocation_threshold),
        alist,
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
    (prio, ps_sig::SigRetrievalRandomness {
        randomness: sig_retrieval_rand,
    })
}

/// a convenient data structure to collect data related to a single AR
pub struct SingleArData<C: Curve> {
    ar_identity:             ArIdentity,
    share:                   Value<C>,
    share_number:            ShareNumber,
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
    aci: &AccCredentialInfo<C, AttributeType>,
    prio: &PreIdentityObject<P, C, AttributeType>,
    cred_counter: u8,
    ip_sig: &ps_sig::Signature<P>,
    policy: &Policy<C, AttributeType>,
    acc_data: &AccountData,
    sig_retrieval_rand: &ps_sig::SigRetrievalRandomness<P>,
) -> CredDeploymentInfo<P, C, AttributeType>
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();

    let alist = &prio.alist;
    let prf_key = aci.prf_key;
    let id_cred_sec = &aci.acc_holder_info.id_cred.id_cred_sec;
    let reg_id_exponent = match aci.prf_key.prf_exponent(cred_counter) {
        Ok(exp) => exp,
        Err(err) => unimplemented!("Handle the (very unlikely) case where K + x = 0, {}", err),
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
    let ar_list = prio.choice_ar_parameters.0.clone();
    let mut choice_ars = Vec::with_capacity(ar_list.len());
    let ip_ar_parameters = &ip_info.ar_info.0.clone();
    for ar in ar_list.iter() {
        match ip_ar_parameters.iter().find(|&x| x.ar_identity == *ar) {
            None => panic!("AR handle not in the IP list"),
            Some(ar_info) => choice_ars.push(ar_info.clone()),
        }
    }
    let choice_ar_parameters = (choice_ars, prio.choice_ar_parameters.1);
    // sharing data for id cred sec
    let (id_cred_data, cmm_id_cred_sec_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data(
        id_cred_sec.view(),
        &choice_ar_parameters,
        &global_context.on_chain_commitment_key,
    );
    let number_of_ars = prio.choice_ar_parameters.0.len();
    // filling ar data
    let mut ar_data: Vec<ChainArData<C>> = Vec::with_capacity(number_of_ars);
    for item in id_cred_data.iter() {
        ar_data.push(ChainArData {
            ar_identity:              item.ar_identity,
            enc_id_cred_pub_share:    item.encrypted_share,
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
        threshold: prio.choice_ar_parameters.1,
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
            None => panic!("cannot find Ar"), // FIXME, should not panic here, handle errors
            // gracefully
            Some(ar_info) => {
                let secret = com_enc_eq::ComEncEqSecret {
                    value:         &item.share,
                    elgamal_rand:  &item.encryption_randomness,
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
    );

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

    CredDeploymentInfo {
        values: cred_values,
        proofs: cdp,
    }
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
) -> com_eq_sig::ComEqSigProof<P, C> {
    let att_vec = &alist.alist;
    // number of user chosen attributes (+2 is for variant and expiry)
    let num_user_attributes = att_vec.len() + 2;
    // To these there are always two attributes (idCredSec and prf key) added.
    let num_total_attributes = num_user_attributes + 2;
    let num_ars = ar_list.len(); // we commit to each anonymity revoker, with randomness 0
                                 // and finally we also commit to the anonymity revocation threshold.
                                 // so the total number of commitments is as follows
    let num_total_commitments = num_total_attributes + num_ars + 1;

    let y_tildas = &ip_pub_key.y_tildas;
    // FIXME: Handle errors more gracefully, or explicitly state precondition.
    assert!(y_tildas.len() >= num_total_attributes);

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

    let variant_val = Value::new(C::scalar_from_u64(u64::from(alist.variant)));
    let variant_cmm = commitment_key.hide(&variant_val, &zero);

    let expiry_val = Value::new(C::scalar_from_u64(alist.expiry));
    let expiry_cmm = commitment_key.hide(&expiry_val, &zero);

    secrets.push((variant_val, &zero));
    gxs.push(y_tildas[num_ars + 3]);
    secrets.push((expiry_val, &zero));
    gxs.push(y_tildas[num_ars + 4]);

    // FIXME: Likely we need to make sure there are enough y_tildas first and fail
    // gracefully otherwise.
    for (idx, &g) in y_tildas.iter().enumerate().take(att_vec.len()) {
        secrets.push((
            Value {
                value: att_vec[idx].to_field_element(),
            },
            // if we commited with non-zero randomness get it.
            // otherwise we must have commited with zero randomness
            // which we should use
            &att_rands.get(&idx).unwrap_or(&zero),
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

    comm_vec.push(variant_cmm);
    comm_vec.push(expiry_cmm);

    for (idx, v) in alist.alist.iter().enumerate() {
        match commitments.cmm_attributes.get(&(idx as u16)) {
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
    com_eq_sig::prove_com_eq_sig::<P, C, R>(
        ro,
        blinded_sig,
        &comm_vec,
        ip_pub_key,
        commitment_key,
        &secret,
        csprng,
    )
}

pub struct CommitmentsRandomness<'a, C: Curve> {
    id_cred_sec_rand:  &'a PedersenRandomness<C>,
    prf_rand:          PedersenRandomness<C>,
    cred_counter_rand: PedersenRandomness<C>,
    attributes_rand:   HashMap<usize, PedersenRandomness<C>>,
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
    for (i, val) in att_vec.iter().enumerate() {
        // in case the value is openened there is no need to hide it.
        // We can just commit with randomness 0.
        if !policy.policy_vec.contains_key(&(i as u16)) {
            let value = Value::new(val.to_field_element());
            let (cmm, rand) = commitment_key.commit(&value, csprng);
            cmm_attributes.insert(i as u16, cmm);
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
        rands:  &rands,
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
