use crate::types::*;
use curve_arithmetic::curve_arithmetic::*;
use elgamal::public::PublicKey;
use pairing::Field;
use pedersen_scheme::{commitment::Commitment, key::CommitmentKey};
use ps_sig;
use rand::*;
use sigma_protocols::{com_enc_eq::*, com_eq::*, com_eq_different_groups::*};

#[derive(Debug, Clone, Copy)]
pub struct Declined(pub Reason);

#[derive(Debug, Clone, Copy)]
pub enum Reason {
    FailedToVerifyKnowledgeOfIdCredSec,
    FailedToVerifyPrfData,
    WrongArParameters,
}

fn check_ar_parameters<C: Curve>(
    _choice_ar_parameters: &(Vec<ArInfo<C>>, u64),
    _ip_ar_info: &Vec<ArInfo<C>>,
) -> bool {
    // some business logic here
    true
}
pub fn verify_credentials<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObject<P, C, AttributeType>,
    // context: Context<P, C>,
    ip_info: &IpInfo<P, C>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Declined> {
    let dlog_base = ip_info.dlog_base;
    let commitment_key_sc = CommitmentKey(ip_info.ip_verify_key.2[0], dlog_base);
    let commitment_key_prf = CommitmentKey(ip_info.ip_verify_key.2[1], dlog_base);

    let b_1 = verify_knowledge_of_id_cred_sec::<P::G_1>(
        &dlog_base,
        &commitment_key_sc,
        &pre_id_obj.id_cred_pub_ip,
        &pre_id_obj.cmm_sc,
        &pre_id_obj.pok_sc,
    );
    if !b_1 {
        return Err(Declined(Reason::FailedToVerifyKnowledgeOfIdCredSec));
    }

    let ar_ck = ip_info.ar_info.1;
    let b_11 = verify_knowledge_of_id_cred_sec::<C>(
        &C::one_point(),
        &ar_ck,
        &pre_id_obj.id_cred_pub,
        &pre_id_obj.snd_cmm_sc,
        &pre_id_obj.snd_pok_sc,
        
        );
    if !b_11{
        return Err(Declined(Reason::FailedToVerifyKnowledgeOfIdCredSec));
    }

    let b_111 = verify_com_eq_diff_grps::<P::G_1, C>(
          &[],
          &((commitment_key_sc.0, commitment_key_sc.1), (ar_ck.0, ar_ck.1)),
          &(pre_id_obj.cmm_sc.0, pre_id_obj.snd_cmm_sc.0),
          &pre_id_obj.proof_com_eq_sc,
      );
    if !b_111{
        return Err(Declined(Reason::FailedToVerifyKnowledgeOfIdCredSec));
    }

    let choice_ar_handles = pre_id_obj.choice_ar_parameters.0.clone();
    let revocation_threshold = pre_id_obj.choice_ar_parameters.1;

    let number_of_ars = choice_ar_handles.len();
    let mut choice_ars = Vec::with_capacity(number_of_ars);
    for ar in choice_ar_handles.iter() {
        match ip_info.ar_info.0.iter().find(|&x| x.ar_identity == *ar) {
            None => return Err(Declined(Reason::WrongArParameters)),
            Some(ar_info) => choice_ars.push(ar_info.clone()),
        }
    }

    // VRF
    let choice_ar_parameters = (choice_ars, revocation_threshold);
    if !check_ar_parameters(&choice_ar_parameters, &ip_info.ar_info.0) {
        return Err(Declined(Reason::WrongArParameters));
    }
    // ar commitment key
    let ar_ck = ip_info.ar_info.1;
    let b_2 = verify_vrf_key_data(
        &commitment_key_prf,
        &pre_id_obj.cmm_prf,
        &ar_ck,
        &pre_id_obj.cmm_prf_sharing_coeff,
        &pre_id_obj.ip_ar_data,
        &choice_ar_parameters.0,
        &pre_id_obj.proof_com_eq,
    );

    if !b_2 {
        return Err(Declined(Reason::FailedToVerifyPrfData));
    }
    let message: ps_sig::UnknownMessage<P> = compute_message(
        &pre_id_obj.cmm_prf,
        &pre_id_obj.cmm_sc,
        &choice_ar_handles,
        &pre_id_obj.alist,
        &ip_info.ip_verify_key,
    );
    let mut csprng = thread_rng();
    Ok(ip_secret_key.sign_unknown_message(&message, &mut csprng))
}

fn compute_message<P: Pairing, AttributeType: Attribute<P::ScalarField>>(
    cmm_prf: &Commitment<P::G_1>,
    cmm_sc: &Commitment<P::G_1>,
    ar_list: &Vec<u64>,
    att_list: &AttributeList<P::ScalarField, AttributeType>,
    ps_public_key: &ps_sig::PublicKey<P>,
) -> ps_sig::UnknownMessage<P> {
    // TODO: handle the errors
    let variant = P::G_1::scalar_from_u64(u64::from(att_list.variant)).unwrap();
    let expiry = P::G_1::scalar_from_u64(att_list.expiry).unwrap();
    let mut message = cmm_sc.0;
    message = message.plus_point(&cmm_prf.0);
    let att_vec = &att_list.alist;
    let n = att_vec.len();
    let m = ar_list.len();
    let key_vec = &ps_public_key.2;
    assert!(key_vec.len() >= n + 4);
    message = message.plus_point(&key_vec[2].mul_by_scalar(&variant));
    message = message.plus_point(&key_vec[3].mul_by_scalar(&expiry));
    for i in 4..(n + 4) {
        let att = att_vec[i - 4].to_field_element();
        message = message.plus_point(&key_vec[i].mul_by_scalar(&att))
    }
    for i in (n + 4)..(m + n + 4) {
        let ar_handle = <P::G_1 as Curve>::scalar_from_u64(ar_list[i - n - 4] as u64).unwrap();
        message = message.plus_point(&key_vec[i].mul_by_scalar(&ar_handle));
    }

    ps_sig::UnknownMessage(message)
}

fn verify_knowledge_of_id_cred_sec<C: Curve>(
    base: &C,
    ck: &CommitmentKey<C>,
    pk: &C,
    commitment: &Commitment<C>,
    proof: &ComEqProof<C>,
) -> bool {
    let Commitment(c) = commitment;
    let CommitmentKey(h, g) = ck;
    verify_com_eq(&[], &(vec![*c], *pk), &(*h, *g, vec![*base]), &proof)
}

fn verify_vrf_key_data<C1: Curve, C2: Curve<Scalar = C1::Scalar>>(
    ip_commitment_key: &CommitmentKey<C1>,
    cmm_vrf: &Commitment<C1>,
    ar_commitment_key: &CommitmentKey<C2>,
    cmm_sharing_coeff: &Vec<Commitment<C2>>,
    ip_ar_data: &Vec<IpArData<C2>>,
    choice_ar_parameters: &Vec<ArInfo<C2>>,
    com_eq_diff_grps_proof: &ComEqDiffGrpsProof<C1, C2>,
) -> bool {
    let CommitmentKey(g_1, h_1) = ip_commitment_key;
    let CommitmentKey(g_2, h_2) = ar_commitment_key;
    let Commitment(cmm_vrf_point) = cmm_vrf;
    let Commitment(cmm_vrf_point_ar_group) = cmm_sharing_coeff[0];
    let b_1 = verify_com_eq_diff_grps::<C1, C2>(
        &[],
        &((*g_1, *h_1), (*g_2, *h_2)),
        &(*cmm_vrf_point, cmm_vrf_point_ar_group),
        com_eq_diff_grps_proof,
    );
    if !b_1 {
        return false;
    }
    // let cmm_to_shares = Vec::new();
    for ar in ip_ar_data.iter() {
        let cmm_share = commitment_to_share(ar.prf_key_share_number, cmm_sharing_coeff);
        // finding the right encryption key

        match choice_ar_parameters
            .into_iter()
            .find(|&x| x.ar_identity == ar.ar_identity)
        {
            None => return false,
            Some(ar_info) => {
                let (g, h) = (PublicKey::generator(), ar_info.ar_public_key.0);
                let (e_1, e_2) = (ar.enc_prf_key_share.0, ar.enc_prf_key_share.1);
                let coeff = (g, h, *g_2, *h_2);
                let eval = (e_1, e_2, cmm_share.0);
                if !verify_com_enc_eq(&[], &coeff, &eval, &ar.proof_com_enc_eq) {
                    return false;
                }
            }
        }
    }
    true
}

#[inline(always)]
pub fn commitment_to_share<C: Curve>(
    share_number: u64,
    coeff_commitments: &Vec<Commitment<C>>,
) -> Commitment<C> {
    let deg = coeff_commitments.len() - 1;
    let mut cmm_share_point: C = coeff_commitments[0].0;
    for i in 1..(deg + 1) {
        let j_pow_i: C::Scalar = C::scalar_from_u64(share_number as u64)
            .unwrap()
            .pow([i as u64]);
        let Commitment(cmm_point) = coeff_commitments[i];
        let a = cmm_point.mul_by_scalar(&j_pow_i);
        cmm_share_point = cmm_share_point.plus_point(&a);
    }
    Commitment(cmm_share_point)
}
