use crate::types::*;
use curve_arithmetic::curve_arithmetic::*;
use pairing::Field;
use pedersen_scheme::{commitment::Commitment, key::CommitmentKey};
use ps_sig;
use rand::*;
use sigma_protocols::{com_enc_eq::*, com_eq::*, com_eq_different_groups::*};
use elgamal::public::PublicKey;

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
    context: Context<P, C>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Declined> {
    // IDCredSec
    let comm_sc_params =
        CommitmentParams((context.commitment_key_sc.0, context.commitment_key_sc.1));

    let b_1 = verify_knowledge_of_id_cred_sec::<P::G_1>(
        &context.dlog_base,
        &comm_sc_params,
        &pre_id_obj.id_cred_pub_ip,
        &pre_id_obj.cmm_sc,
        &pre_id_obj.pok_sc,
    );
    if !b_1 {
        return Err(Declined(Reason::FailedToVerifyKnowledgeOfIdCredSec));
    }

    // VRF
    if !check_ar_parameters(&context.choice_ar_parameters, &context.ip_info.ar_info.0) {
        return Err(Declined(Reason::WrongArParameters));
    }
    // ar commitment key
    let ar_ck = context.ip_info.ar_info.1;
    let b_2 = verify_vrf_key_data(
        &context.commitment_key_prf,
        &pre_id_obj.cmm_prf,
        &ar_ck,
        &pre_id_obj.cmm_prf_sharing_coeff,
        &pre_id_obj.ip_ar_data,
        &context.choice_ar_parameters.0,
        &pre_id_obj.proof_com_eq,
    );

    if !b_2 {
        return Err(Declined(Reason::FailedToVerifyPrfData));
    }
    let message: ps_sig::UnknownMessage<P> = compute_message(
        &pre_id_obj.cmm_prf,
        &pre_id_obj.cmm_sc,
        &pre_id_obj.alist,
        &context.ip_info.ip_verify_key,
    );
    let mut csprng = thread_rng();
    Ok(ip_secret_key.sign_unknown_message(&message, &mut csprng))
}

fn compute_message<P: Pairing, AttributeType: Attribute<P::ScalarField>>(
    cmm_prf: &Commitment<P::G_1>,
    cmm_sc: &Commitment<P::G_1>,
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
    let key_vec = &ps_public_key.2;
    assert!(key_vec.len() >= n + 4);
    message = message.plus_point(&key_vec[2].mul_by_scalar(&variant));
    message = message.plus_point(&key_vec[3].mul_by_scalar(&expiry));
    for i in 4..(n + 4) {
        let att = att_vec[i - 4].to_field_element();
        message = message.plus_point(&key_vec[i].mul_by_scalar(&att))
    }

    ps_sig::UnknownMessage(message)
}

fn verify_knowledge_of_id_cred_sec<C: Curve>(
    base: &C,
    cmm_params: &CommitmentParams<C>,
    pk: &C,
    commitment: &Commitment<C>,
    proof: &ComEqProof<C>,
) -> bool {
    let Commitment(c) = commitment;
    let CommitmentParams((h, g)) = cmm_params;
    verify_com_eq(&[], &(vec![*c], *pk), &(*h, *g, vec![*base]), &proof)
}

fn verify_vrf_key_data<C1: Curve, C2: Curve<Scalar = C1::Scalar>>(
    ip_commitment_key: &CommitmentKey<C1>,
    cmm_vrf: &Commitment<C1>,
    ar_commitment_key: &CommitmentKey<C2>,
    cmm_sharing_coeff: &Vec<(u64, Commitment<C2>)>,
    ip_ar_data: &Vec<IpArData<C2>>,
    choice_ar_parameters: &Vec<ArInfo<C2>>,
    com_eq_diff_grps_proof: &ComEqDiffGrpsProof<C1, C2>,
) -> bool {
    let CommitmentKey(g_1, h_1) = ip_commitment_key;
    let CommitmentKey(g_2, h_2) = ar_commitment_key;
    let Commitment(cmm_vrf_point) = cmm_vrf;
    let (coeff_number, Commitment(cmm_vrf_point_ar_group)) = cmm_sharing_coeff[0];
    assert_eq!(coeff_number, 0);
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
            .find(|&x| x.ar_name == ar.ar_name)
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
    coeff_commitments: &Vec<(u64, Commitment<C>)>,
) -> Commitment<C> {
    let deg = coeff_commitments.len() - 1;
    let mut cmm_share_point: C = (coeff_commitments[0].1).0;
    for i in 1..(deg + 1) {
        let j_pow_i: C::Scalar = C::scalar_from_u64(share_number).unwrap().pow([i as u64]);
        let (s, Commitment(cmm_point)) = coeff_commitments[i];
        assert_eq!(s as usize, i);
        let a = cmm_point.mul_by_scalar(&j_pow_i);
        cmm_share_point = cmm_share_point.plus_point(&a);
    }
    Commitment(cmm_share_point)
}
