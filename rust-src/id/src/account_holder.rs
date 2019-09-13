use crate::types::*;

use sha2::{Digest, Sha512};

use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use elgamal::cipher::Cipher;
use elgamal::public::PublicKey;
use pairing::Field;
use pedersen_scheme::{
    commitment::Commitment,
    key::{CommitmentKey, CommitmentKey as PedersenKey},
    randomness::Randomness,
    value as pedersen,
    value::Value,
};
use ps_sig;
use rand::*;
use secret_sharing::secret_sharing::*;
use sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult};

/// Generate PreIdentityObject out of the account holder information,
/// the chosen anonymity revoker information, and the necessary contextual
/// information (group generators, shared commitment keys, etc).
pub fn generate_pio<
    P: Pairing,
    AttributeType: Attribute<C::Scalar>,
    C: Curve<Scalar = P::ScalarField>,
>(
    context: &Context<P, C>,
    aci: &AccCredentialInfo<P, C, AttributeType>,
) -> (
    PreIdentityObject<P, C, AttributeType>,
    SigRetrievalRandomness<P>,
)
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();
    let id_ah = aci.acc_holder_info.id_ah.clone();
    let id_cred_pub_ip = aci.acc_holder_info.id_cred.id_cred_pub_ip;
    //PRF related computation
    let prf::SecretKey(prf_key_scalar) = aci.prf_key;
    // FIXME: The next item will change to encrypt by chunks to enable anonymity
    // revocation.
    let (prf_key_data, cmm_prf_sharing_coeff, cmm_coeff_randomness) = compute_sharing_data(
        &aci.prf_key.0,
        &context.choice_ar_parameters,
        &context.ip_info.ar_info.1,
    );
    let number_of_ars = context.choice_ar_parameters.0.len();
    let mut ip_ar_data: Vec<IpArData<C>> = Vec::with_capacity(number_of_ars);
    let ar_commitment_key = context.ip_info.ar_info.1;
    for item in prf_key_data.iter() {
        let proof = com_enc_eq::prove_com_enc_eq(
                    &mut csprng,
                    &[],
                    &(
                        item.encrypted_share.0,
                        item.encrypted_share.1,
                        item.cmm_to_share.0,
                    ),
                    &(
                        item.encryption_randomness,
                        item.share,
                        item.randomness_cmm_to_share.0,
                    ),
                    &(
                        PublicKey::generator(),
                        item.ar_public_key.0,
                        ar_commitment_key.0,
                        ar_commitment_key.1,
                    ),
                );
                ip_ar_data.push(IpArData {
                    ar_identity:              item.ar_identity.clone(),
                    enc_prf_key_share:    item.encrypted_share,
                    prf_key_share_number: item.share_number,
                    proof_com_enc_eq:     proof,
                });
            
        
    }
    let alist = aci.attributes.clone();

    let id_cred_sec = aci.acc_holder_info.id_cred.id_cred_sec;
    let sc_ck = &context.commitment_key_sc;
    let (cmm_sc, cmm_sc_rand) = sc_ck.commit(&pedersen::Value(id_cred_sec), &mut csprng);
    let pok_sc = {
        let Commitment(cmm_sc_point) = cmm_sc;
        let CommitmentKey(sc_ck_1, sc_ck_2) = sc_ck;
        com_eq::prove_com_eq(
            &[],
            &(vec![cmm_sc_point], id_cred_pub_ip),
            &(*sc_ck_1, *sc_ck_2, vec![context.dlog_base]),
            &(vec![cmm_sc_rand.0], vec![id_cred_sec]),
            &mut csprng,
        )
    };
    let (cmm_prf, rand_cmm_prf) = context
        .commitment_key_prf
        .commit(&pedersen::Value(prf_key_scalar), &mut csprng);
    let snd_cmm_prf = cmm_prf_sharing_coeff[0].1;
    let rand_snd_cmm_prf = cmm_coeff_randomness[0].1;
    // now generate the proof that the commitment hidden in snd_cmm_prf is to
    // the same prf key as the one encrypted in id_ar_data via anonymity revokers
    // public key.
    let proof_com_eq = {
        let public = (cmm_prf.0, snd_cmm_prf.0);
        // TODO: Check that this is the correct order of secret values.
        let secret = (prf_key_scalar, rand_cmm_prf.0, rand_snd_cmm_prf.0);
        let coeff = (
            (context.commitment_key_prf.0, context.commitment_key_prf.1),
            ((context.ip_info.ar_info.1).0, (context.ip_info.ar_info.1).1),
        );
        com_eq_different_groups::prove_com_eq_diff_grps(&mut csprng, &[], &public, &secret, &coeff)
    };
    let ar_handles = context.choice_ar_parameters.0.iter().map(|x| x.ar_identity).collect();
    let revocation_threshold = context.choice_ar_parameters.1;
    let prio = PreIdentityObject {
        id_ah,
        id_cred_pub_ip,
        ip_ar_data,
        choice_ar_parameters: (ar_handles, revocation_threshold),
        alist,
        cmm_sc,
        pok_sc,
        cmm_prf,
        cmm_prf_sharing_coeff,
        proof_com_eq,
    };
    let mut sig_retrieval_rand = cmm_sc_rand.0;
    sig_retrieval_rand.add_assign(&rand_cmm_prf.0);
    (prio, SigRetrievalRandomness(sig_retrieval_rand))
}

#[derive(Clone)]
pub struct SingleArData<C: Curve> {
    ar_identity:                u64,
    share:                   C::Scalar,
    share_number:            u64,
    encrypted_share:         Cipher<C>,
    encryption_randomness:   C::Scalar,
    cmm_to_share:            Commitment<C>,
    randomness_cmm_to_share: Randomness<C>,
    ar_public_key: elgamal::PublicKey<C>, 
}
#[inline]
pub fn compute_sharing_data<C: Curve>(
    shared_scalar: &C::Scalar,
    ar_parameters: &(Vec<ArInfo<C>>, u64),
    commitment_key: &PedersenKey<C>,
) -> (
    Vec<SingleArData<C>>,
    Vec<(u64, Commitment<C>)>,
    Vec<(u64, Randomness<C>)>,
) {
    let n = ar_parameters.0.len() as u64;
    let t = ar_parameters.1;
    let mut csprng = thread_rng();
    let (cmm_prf, cmm_prf_rand) = commitment_key.commit(&Value(*shared_scalar), &mut csprng);
    let sharing_data = share::<C, ThreadRng>(&shared_scalar, n, t as u64, &mut csprng);
    let mut cmm_sharing_coefficients: Vec<(u64, Commitment<C>)> = Vec::with_capacity(t as usize);
    cmm_sharing_coefficients.push((0, cmm_prf));
    let mut cmm_coeff_randomness: Vec<(u64, Randomness<C>)> = Vec::with_capacity(t as usize);
    cmm_coeff_randomness.push((0, cmm_prf_rand));
    for i in 1..(t as usize) {
        let (cmm, rnd) = commitment_key.commit(
            &Value(sharing_data.coefficients[i as usize - 1].1),
            &mut csprng,
        );
        cmm_sharing_coefficients.push((i as u64, cmm));
        cmm_coeff_randomness.push((i as u64, rnd));
    }
    let mut ar_prf_data: Vec<SingleArData<C>> = Vec::with_capacity(n as usize);
    for i in 1..n + 1 {
        let ar = &ar_parameters.0[(i as usize) - 1];
        let pk = ar.ar_public_key;
        let share = sharing_data.shares[(i as usize) - 1].1;
        assert_eq!(i as u64, sharing_data.shares[(i as usize) - 1].0);
        let (cipher, rnd2) = pk.encrypt_exponent_rand(&mut csprng, &share);
        let (cmm, rnd) =
            commitment_to_share(i as u64, &cmm_sharing_coefficients, &cmm_coeff_randomness);
        // let proof = com_enc_eq::prove_com_enc_eq(&mut csprng, &challenge_prefix,
        // &(cipher.0, cipher.1, cmm.0), &(rnd2, share, rnd.0),
        // &(ar.ar_elgamal_generator, pk.0, commitment_key.0, commitment_key.1));
        let ar_data = SingleArData {
            ar_identity: ar.ar_identity.clone(),
            share,
            share_number: i as u64,
            encrypted_share: cipher,
            encryption_randomness: rnd2,
            cmm_to_share: cmm,
            randomness_cmm_to_share: rnd,
            ar_public_key: pk,
        };
        ar_prf_data.push(ar_data)
    }
    (ar_prf_data, cmm_sharing_coefficients, cmm_coeff_randomness)
}

#[inline(always)]
pub fn commitment_to_share<C: Curve>(
    share_number: u64,
    coeff_commitments: &Vec<(u64, Commitment<C>)>,
    coeff_randomness: &Vec<(u64, Randomness<C>)>,
) -> (Commitment<C>, Randomness<C>) {
    let deg = coeff_commitments.len() - 1;
    let mut cmm_share_point: C = (coeff_commitments[0].1).0;
    let mut cmm_share_randomness_scalar: C::Scalar = (coeff_randomness[0].1).0;
    for i in 1..(deg + 1) {
        let j_pow_i: C::Scalar = C::scalar_from_u64(share_number).unwrap().pow([i as u64]);
        let (s, Commitment(cmm_point)) = coeff_commitments[i];
        assert_eq!(s as usize, i);
        let a = cmm_point.mul_by_scalar(&j_pow_i);
        cmm_share_point = cmm_share_point.plus_point(&a);
        // let mut r = C::scalar_from_u64(coeff_randomness[i].0).unwrap();
        let mut r = (coeff_randomness[i].1).0;
        r.mul_assign(&j_pow_i);
        cmm_share_randomness_scalar.add_assign(&r);
    }
    let cmm = Commitment(cmm_share_point);
    let rnd = Randomness(cmm_share_randomness_scalar);
    (cmm, rnd)
}

#[allow(clippy::too_many_arguments)]
pub fn generate_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    ip_info: &IpInfo<P, C>,
    global_context: &GlobalContext<C>,
    aci: &AccCredentialInfo<P, C, AttributeType>,
    prio: &PreIdentityObject<P, C, AttributeType>,
    cred_counter: u8,
    ip_sig: &ps_sig::Signature<P>,
    policy: &Policy<C, AttributeType>,
    acc_data: &AccountData,
    sig_retrieval_rand: &SigRetrievalRandomness<P>,
) -> CredDeploymentInfo<P, C, AttributeType>
where
    AttributeType: Clone, {
    let mut csprng = thread_rng();

    let commitment_base = global_context.on_chain_commitment_key.0;

    let alist = &prio.alist;
    let prf_key = aci.prf_key;
    let id_cred_sec = aci.acc_holder_info.id_cred.id_cred_sec;
    let reg_id_exponent = match aci.prf_key.prf_exponent(cred_counter) {
        Ok(exp) => exp,
        Err(err) => unimplemented!("Handle the (very unlikely) case where K + x = 0, {}", err),
    };

    let reg_id = commitment_base.mul_by_scalar(&reg_id_exponent);
   
    let ar_list = prio.choice_ar_parameters.0.clone();
    let mut choice_ars= Vec::with_capacity(ar_list.len());
      let ip_ar_parameters = &ip_info.ar_info.0.clone();
      for ar in ar_list.iter(){
          match ip_ar_parameters.into_iter().find(|&x| x.ar_identity == *ar ){
              None => panic!("AR handle not in the IP list"),
              Some(ar_info) => choice_ars.push(ar_info.clone()),

          }

      }
    let choice_ar_parameters = (choice_ars, prio.choice_ar_parameters.1);

    let (id_cred_data, cmm_id_cred_sec_sharing_coeff, cmm_coeff_randomness) =
        compute_sharing_data(&id_cred_sec, &choice_ar_parameters, &global_context.on_chain_commitment_key);
    let number_of_ars = prio.choice_ar_parameters.0.len();
    let mut ar_data: Vec<ChainArData<C>> = Vec::with_capacity(number_of_ars);
    for item in id_cred_data.iter() {
        ar_data.push(ChainArData {
            ar_identity:                  item.ar_identity.clone(),
            enc_id_cred_pub_share:    item.encrypted_share,
            id_cred_pub_share_number: item.share_number,
        });
    }

    let ip_pub_key = &ip_info.ip_verify_key;

    // retrieve the signature on the underlying idcredsec + prf_key + attribute_list
    let retrieved_sig = ps_sig::retrieve_sig(&ip_sig, sig_retrieval_rand.0);

    // and then we blind the signature to disassociate it from the message.
    // only the second part is used (as per the protocol)
    let (blinded_sig, _r, blinded_sig_rand_sec) = ps_sig::blind_sig(&retrieved_sig, &mut csprng);
    

    // We now compute commitments to all the items in the attribute list.
    // We use the on-chain pedersen commitment key.
    let (commitments, commitment_rands) = compute_commitments(
        &global_context.on_chain_commitment_key,
        &alist,
        &ar_list,
        &prf_key,
        cred_counter,
        &cmm_id_cred_sec_sharing_coeff,
        &cmm_coeff_randomness,
        &mut csprng,
    );

    // We have all the values now.
    // FIXME: With more uniform infrastructure we can avoid all the cloning here.
    let cred_values = CredentialDeploymentValues {
        acc_scheme_id: SchemeId::Ed25519,
        reg_id,
        ar_data,
        choice_ar_handles: ar_list,
        ip_identity: ip_info.ip_identity.clone(),
        policy: policy.clone(),
        acc_pub_key: acc_data.verify_key,
    };

    // Compute the challenge prefix by hashing the values.
    let mut hasher = Sha512::new();
    hasher.input(&cred_values.to_bytes());
    let challenge_prefix = hasher.result();

    let mut pok_id_cred_pub = Vec::with_capacity(number_of_ars);
    for item in id_cred_data.iter() {
        match choice_ar_parameters.0.iter()
            .find(|&x| x.ar_identity == item.ar_identity)
        {
            None => panic!("cannot find Ar"),
            Some(ar_info) => {
                let proof = com_enc_eq::prove_com_enc_eq(
                    &mut csprng,
                    &challenge_prefix,
                    &(
                        item.encrypted_share.0,
                        item.encrypted_share.1,
                        item.cmm_to_share.0,
                    ),
                    &(
                        item.encryption_randomness,
                        item.share,
                        item.randomness_cmm_to_share.0,
                    ),
                    &(
                        PublicKey::generator(),
                        ar_info.ar_public_key.0,
                        global_context.on_chain_commitment_key.0,
                        global_context.on_chain_commitment_key.1,
                    ),
                );
                pok_id_cred_pub.push((item.share_number, proof));
            }
        }
    }
    // and then use it to generate all the proofs.

    // Compute the proof of the fact that the encryption of idcredpub we
    // computed above corresponds to the same id_cred_sec that is signed by the
    // identity provider (and commited to)

    //    let pok_id_cred_pub = compute_pok_id_cred_pub(
    //        &challenge_prefix,
    //        &ip_info,
    //        &global_context,
    //        &id_cred_sec,
    //        &id_cred_pub_enc,
    //        &id_cred_pub_rand,
    //        &commitments.cmm_id_cred_sec,
    //        &commitment_rands.id_cred_sec_rand.0,
    //        &mut csprng,
    //    );

    // Proof that the registration id is computed correctly from the prf key K and
    // the cred_counter x. At the moment there is no proof that x is less than
    // max_account.
    let pok_reg_id = compute_pok_reg_id(
        &challenge_prefix,
        &global_context.on_chain_commitment_key,
        prf_key,
        &commitments.cmm_prf,
        commitment_rands.prf_rand.0,
        cred_counter,
        &commitments.cmm_cred_counter,
        commitment_rands.cred_counter_rand.0,
        reg_id_exponent,
        reg_id,
        &mut csprng,
    );

    // Proof of knowledge of the signature of the identity provider.
    let pok_sig = compute_pok_sig(
        &challenge_prefix,
        &global_context.on_chain_commitment_key,
        &commitments,
        &commitment_rands,
        &id_cred_sec,
        &prf_key,
        &alist,
        &cred_values.choice_ar_handles,
        &ip_pub_key,
        &blinded_sig,
        &blinded_sig_rand_sec,
        &mut csprng,
    );

    // Proof of knowledge of the secret key corresponding to the public
    // (verification) key.
    let proof_acc_sk =
        eddsa_dlog::prove_dlog_ed25519(&challenge_prefix, &acc_data.verify_key, &acc_data.sign_key);
    let cdp = CredDeploymentProofs {
        sig: blinded_sig,
        commitments,
        proof_id_cred_pub: pok_id_cred_pub,
        proof_ip_sig: pok_sig,
        proof_reg_id: pok_reg_id,
        proof_acc_sk,
        proof_policy: open_policy_commitments(&policy, &commitment_rands),
    };

    CredDeploymentInfo {
        values: cred_values,
        proofs: cdp,
    }
}

fn open_policy_commitments<C: Curve, AttributeType: Attribute<C::Scalar>>(
    policy: &Policy<C, AttributeType>,
    commitment_rands: &CommitmentsRandomness<C>,
) -> PolicyProof<C> {
    // FIXME: Handle this more resiliantly.
    let att_rands = &commitment_rands.attributes_rand;
    assert!(att_rands.len() >= 2);
    let variant_rand = att_rands[0];
    let expiry_rand = att_rands[1];
    // FIXME: Handle out-of-range.
    let cmm_opening_map = policy
        .policy_vec
        .iter()
        .map(|(idx, _)| (*idx, att_rands[*idx as usize + 2].0))
        .collect();
    PolicyProof {
        variant_rand: variant_rand.0,
        expiry_rand: expiry_rand.0,
        cmm_opening_map,
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_pok_sig<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
    R: Rng,
>(
    challenge_prefix: &[u8],
    commitment_key: &PedersenKey<C>,
    commitments: &CredDeploymentCommitments<C>,
    commitment_rands: &CommitmentsRandomness<C>,
    id_cred_sec: &P::ScalarField,
    prf_key: &prf::SecretKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ar_list:&Vec<u64>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    blinded_sig: &ps_sig::Signature<P>,
    blinded_sig_rand_sec: &P::ScalarField,
    csprng: &mut R,
) -> com_eq_sig::ComEqSigProof<P, C> {
    let att_vec = &alist.alist;
    // number of user chosen attributes. To these there are always
    // two attributes (idCredSec and prf key added).
    let num_user_attributes = att_vec.len() + 2;
    let num_total_attributes = num_user_attributes + 2;
    let num_ars = commitments.cmm_ars.len();
    let num_total_commitments = num_total_attributes + num_ars;


    let ps_sig::Signature(a, b) = blinded_sig;
    let (eval_pair, eval) = (b, P::G_2::one_point());
    let (g_base, h_base) = ((commitment_key.0), commitment_key.1);
    let ps_sig::PublicKey(_gen1, _gen2, _, yxs, ip_pub_key_x) = ip_pub_key;
    assert!(yxs.len() >= num_total_attributes);

    let (p_pair, p) = (a, ip_pub_key_x);

    let (q_pair, q) = (a, P::G_2::one_point());
    let q_sec = blinded_sig_rand_sec;

    let mut gxs = Vec::with_capacity(num_total_commitments);
    let mut gxs_sec = Vec::with_capacity(num_total_commitments);
    gxs_sec.push(*id_cred_sec);
    gxs.push(yxs[0]);
    let prf_key_scalar = prf_key.0;
    gxs_sec.push(prf_key_scalar);
    gxs.push(yxs[1]);
    gxs_sec.push(C::scalar_from_u64(u64::from(alist.variant)).unwrap());
    gxs.push(yxs[2]);
    gxs_sec.push(C::scalar_from_u64(alist.expiry).unwrap());
    gxs.push(yxs[3]);
    for i in 4..num_total_attributes {
        gxs_sec.push(att_vec[i - 4].to_field_element());
        gxs.push(yxs[i]);
    }
    for i in num_total_attributes..num_total_commitments {
          gxs_sec.push(<P::G_1 as Curve>::scalar_from_u64(ar_list[i-num_total_attributes]).unwrap());
          gxs.push(yxs[i]);
    }

    let gxs_pair = a; // CHECK with Bassel

    let mut pedersen_rands = Vec::with_capacity(num_total_commitments);
    pedersen_rands.push(commitment_rands.id_cred_sec_rand);
    pedersen_rands.push(commitment_rands.prf_rand);
    pedersen_rands.extend_from_slice(&commitment_rands.attributes_rand);
    for _ar in ar_list.iter(){
        pedersen_rands.push(Randomness(C::Scalar::zero()));
    }

    let mut comm_vec = Vec::with_capacity(num_total_attributes);
    comm_vec.push(commitments.cmm_id_cred_sec.0);
    comm_vec.push(commitments.cmm_prf.0);
    for v in commitments.cmm_attributes.iter() {
        comm_vec.push(v.0);
    }

    for ar in commitments.cmm_ars.iter(){
        comm_vec.push(ar.0);
    }
    com_eq_sig::prove_com_eq_sig::<P, C, R>(
        &challenge_prefix,
        &((*eval_pair, eval), comm_vec),
        &(
            (*p_pair, *p),
            (*q_pair, q),
            (*gxs_pair, gxs),
            (g_base, h_base),
        ),
        &(
            (*q_sec, gxs_sec),
            pedersen_rands.iter().map(|x| x.0).collect(),
        ),
        csprng,
    )
}

pub struct CommitmentsRandomness<C: Curve> {
    id_cred_sec_rand:  Randomness<C>,
    prf_rand:          Randomness<C>,
    cred_counter_rand: Randomness<C>,
    // variant_rand     : C::Scalar,
    // expirty_rand     : C::Scalar,
    attributes_rand: Vec<Randomness<C>>,
}

fn compute_commitments<C: Curve, AttributeType: Attribute<C::Scalar>, R: Rng>(
    commitment_key: &PedersenKey<C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ar_list: &Vec<u64>,
    prf_key: &prf::SecretKey<C>,
    cred_counter: u8,
    cmm_id_cred_sec_sharing_coeff: &Vec<(u64, Commitment<C>)>,
    cmm_coeff_randomness: &Vec<(u64, Randomness<C>)>,
    csprng: &mut R,
) -> (CredDeploymentCommitments<C>, CommitmentsRandomness<C>) {
    let (c, cmm_id_cred_sec) = cmm_id_cred_sec_sharing_coeff[0];
    assert_eq!(c, 0);
    let (cc, id_cred_sec_rand) = cmm_coeff_randomness[0];
    assert_eq!(cc, 0);
    let (cmm_id_cred_sec, id_cred_sec_rand) = (cmm_id_cred_sec, id_cred_sec_rand);
    let prf::SecretKey(prf_scalar) = prf_key;
    let (cmm_prf, prf_rand) = commitment_key.commit(&Value(*prf_scalar), csprng);
    let variant_scalar = C::scalar_from_u64(u64::from(alist.variant)).unwrap();
    let (cmm_variant, variant_rand) = commitment_key.commit(&Value(variant_scalar), csprng);
    let expiry_scalar = C::scalar_from_u64(alist.expiry as u64).unwrap();
    let (cmm_expiry, expiry_rand) = commitment_key.commit(&Value(expiry_scalar), csprng);
    let cred_counter_scalar = C::scalar_from_u64(u64::from(cred_counter)).unwrap();
    let (cmm_cred_counter, cred_counter_rand) =
        commitment_key.commit(&Value(cred_counter_scalar), csprng);
    let att_vec = &alist.alist;
    let n = att_vec.len();
    let mut cmm_attributes = Vec::with_capacity(n + 2);
    let mut attributes_rand = Vec::with_capacity(n + 2);
    cmm_attributes.push(cmm_variant);
    attributes_rand.push(variant_rand);
    cmm_attributes.push(cmm_expiry);
    attributes_rand.push(expiry_rand);
    for val in att_vec.iter() {
        let (cmm, rand) = commitment_key.commit(&Value(val.to_field_element()), csprng);
        cmm_attributes.push(cmm);
        attributes_rand.push(rand);
    }
    let m = ar_list.len();
    let mut cmm_ars = Vec::with_capacity(m);
    for ar in ar_list.iter(){
        cmm_ars.push(commitment_key.hide(&Value(C::scalar_from_u64(*ar).unwrap()), &Randomness(C::Scalar::zero())));
    }
    let cdc = CredDeploymentCommitments {
        cmm_id_cred_sec,
        cmm_prf,
        cmm_cred_counter,
        cmm_attributes,
        cmm_ars,
        cmm_id_cred_sec_sharing_coeff: cmm_id_cred_sec_sharing_coeff.clone(),
    };

    let cr = CommitmentsRandomness {
        id_cred_sec_rand,
        prf_rand,
        cred_counter_rand,
        attributes_rand,
    };

    (cdc, cr)
}

#[allow(clippy::too_many_arguments)]
fn compute_pok_reg_id<C: Curve, R: Rng>(
    challenge_prefix: &[u8],
    on_chain_commitment_key: &PedersenKey<C>,
    prf_key: prf::SecretKey<C>,
    cmm_prf: &Commitment<C>,
    prf_rand: C::Scalar,
    cred_counter: u8,
    cmm_cred_counter: &Commitment<C>,
    cred_counter_rand: C::Scalar,
    reg_id_exponent: C::Scalar,
    reg_id: C,
    csprng: &mut R,
) -> com_mult::ComMultProof<C> {
    // coefficients of the protocol derived from the pedersen key
    let g = on_chain_commitment_key.0;
    let h = on_chain_commitment_key.1;

    let coeff = [g, h];

    // commitments are the public values.
    let public = [cmm_prf.0.plus_point(&cmm_cred_counter.0), reg_id, g];
    // finally the secret keys are derived from actual commited values
    // and the randomness.

    let mut k = prf_key.0;
    // FIXME: Handle the error case (which cannot happen for the current curve, but
    // in general ...)
    k.add_assign(&C::scalar_from_u64(u64::from(cred_counter)).unwrap());
    let mut rand_1 = prf_rand;
    rand_1.add_assign(&cred_counter_rand);
    let s1 = (k, rand_1);
    // reg_id is the commitment to reg_id_exponent with randomness 0
    let s2 = (reg_id_exponent, C::Scalar::zero());
    // the right-hand side of the equation is commitment to 1 with randomness 0
    let s3 = (C::Scalar::one(), C::Scalar::zero());

    let secret = [s1, s2, s3];

    com_mult::prove_com_mult(csprng, &challenge_prefix, &public, &secret, &coeff)
}
// #[allow(clippy::too_many_arguments)]
// fn compute_pok_id_cred_pub<P: Pairing, C: Curve<Scalar = P::ScalarField>, R:
// Rng>( challenge_prefix: &[u8],
// ip_info: &IpInfo<P, C>,
// global_context: &GlobalContext<C>,
// id_cred_sec: &C::Scalar,
// id_cred_pub_enc: &Cipher<C>,
// id_cred_pub_rand: &C::Scalar,
// cmm_id_cred_sec: &Commitment<C>,
// id_cred_sec_rand: &C::Scalar,
// csprng: &mut R,
// ) -> com_enc_eq::ComEncEqProof<C> {
// let public = (id_cred_pub_enc.0, id_cred_pub_enc.1, cmm_id_cred_sec.0);
// FIXME: The one_point needs to be a parameter.
// let ar_info = &ip_info.ar_info;
// let cmm_key = &global_context.on_chain_commitment_key;
// let base = (
// ar_info.ar_elgamal_generator,
// ar_info.ar_public_key.0,
// cmm_key.0,
// cmm_key.1,
// );
// let secret = (*id_cred_pub_rand, *id_cred_sec, *id_cred_sec_rand);
//
// com_enc_eq::prove_com_enc_eq::<C, R>(csprng, &challenge_prefix, &public,
// &secret, &base) }
