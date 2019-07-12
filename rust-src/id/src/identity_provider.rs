use crate::types::*;
use curve_arithmetic::curve_arithmetic::*;
use elgamal::cipher::Cipher;
use pedersen_scheme::commitment::Commitment as PedersenCommitment;
use ps_sig;
use rand::*;
use sigma_protocols::{com_enc_eq::*, com_eq_different_groups::*, dlog::*, com_eq::*};

#[derive(Debug, Clone, Copy)]
pub struct Declined(pub Reason);

#[derive(Debug, Clone, Copy)]
pub enum Reason {
    FailedToVerifyKnowledgeOfIdCredSec,
    FailedToVerifyPrfData,
}

pub fn verify_credentials<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObject<P, C, AttributeType >,
    context: Context<P, C>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Declined> {
    let comm_sc_params = CommitmentParams((
        context.commitment_key_sc.0[0],
        context.commitment_key_sc.1,
    ));

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

    let comm_1_params = CommitmentParams((
        context.commitment_key_prf.0[0],
        context.commitment_key_prf.1,
    ));
    let comm_2_params =
        CommitmentParams((context.commitment_key_ar.0[0], context.commitment_key_ar.1));
    let ar_info = context.ip_info.ar_info;
    let elgamal_params = ElgamalParams((ar_info.ar_elgamal_generator, ar_info.ar_public_key.0));
    let b_2 = verify_vrf_key_data(
        &comm_1_params,
        &pre_id_obj.cmm_prf,
        &comm_2_params,
        &pre_id_obj.snd_cmm_prf,
        &elgamal_params,
        &pre_id_obj.ip_ar_data.prf_key_enc,
        &pre_id_obj.proof_com_eq,
        &pre_id_obj.proof_com_enc_eq,
    );
    if !b_2 {
        return Err(Declined(Reason::FailedToVerifyPrfData));
    }
    let message: ps_sig::UnknownMessage<P> = compute_message(
        &pre_id_obj.id_cred_pub_ip,
        &pre_id_obj.cmm_prf,
        &pre_id_obj.cmm_sc,
        &pre_id_obj.alist,
        &context.ip_info.ip_verify_key,
    );
    let mut csprng = thread_rng();
    Ok(ip_secret_key.sign_unknown_message(&message, &mut csprng))
}

fn compute_message<P: Pairing, AttributeType: Attribute<P::ScalarField>>(
    id_cred_pub: &P::G_1,
    cmm_prf: &PedersenCommitment<P::G_1>,
    cmm_sc: &PedersenCommitment<P::G_1>,
    att_list: &AttributeList<P::ScalarField, AttributeType>,
    ps_public_key: &ps_sig::PublicKey<P>,
) -> ps_sig::UnknownMessage<P> {
    //TODO: handle the errors
    let variant = P::G_1::scalar_from_u64(att_list.variant as u64).unwrap();
    let expiry = P::G_1::scalar_from_u64(att_list.expiry.timestamp() as u64).unwrap();
    let mut message = cmm_sc.0;
    message = message.plus_point(&cmm_prf.0);
    let att_vec = &att_list.alist;
    let n = att_vec.len();
    let key_vec = &ps_public_key.2;
    assert!(key_vec.len() >= n + 4);
    message = message.plus_point(&key_vec[2].mul_by_scalar(&variant));
    message = message.plus_point(&key_vec[3].mul_by_scalar(&expiry));
    for i in 4..(n + 2) {
        let att = att_vec[i - 4].to_field_element();
        message = message.plus_point(&key_vec[i].mul_by_scalar(&att))
    }

    ps_sig::UnknownMessage(message)
}

fn verify_knowledge_of_id_cred_sec<C: Curve>(
    base: &C,
    cmm_params: &CommitmentParams<C>,
    pk: &C,
    commitment: &PedersenCommitment<C>,
    proof: &ComEqProof<C>,
) -> bool {
    let PedersenCommitment(c) = commitment;
    let CommitmentParams((h, g)) = cmm_params;
    verify_com_eq(&(vec![*c],*pk),&(*h,*g, vec![*base]), &proof)
}

fn verify_vrf_key_data<C_1: Curve, C_2: Curve<Scalar = C_1::Scalar>>(
    comm_1_params: &CommitmentParams<C_1>,
    comm_1: &PedersenCommitment<C_1>,
    comm_2_params: &CommitmentParams<C_2>,
    comm_2: &PedersenCommitment<C_2>,
    elgamal_params: &ElgamalParams<C_2>,
    cipher: &Cipher<C_2>,
    com_eq_diff_grps_proof: &ComEqDiffGrpsProof<C_1, C_2>,
    comm_enc_eq_proof: &ComEncEqProof<C_2>,
) -> bool {
    let (g_1, h_1) = comm_1_params.0;
    let (g_2, h_2) = comm_2_params.0;
    let c_1 = comm_1.0;
    let c_2 = comm_2.0;
    let b_1 = verify_com_eq_diff_grps(
        &((g_1, h_1), (g_2, h_2)),
        &(c_1, c_2),
        com_eq_diff_grps_proof,
    );
    if !b_1 {
        return false;
    }
    let (g, h) = elgamal_params.0;
    let (e_1, e_2) = (cipher.0, cipher.1);
    let coeff = (g, h, g_2, h_2);
    let eval = (e_1, e_2, c_2);
    verify_com_enc_eq(&coeff, &eval, comm_enc_eq_proof)
}
