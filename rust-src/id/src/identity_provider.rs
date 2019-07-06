use crate::types::*;
use curve_arithmetic::curve_arithmetic::*;
use either::*;
use elgamal::cipher::Cipher;
use pedersen_scheme::commitment::Commitment as PedersenCommitment;
use ps_sig;
use rand::*;
use sigma_protocols::{com_enc_eq::*, com_eq_different_groups::*, dlog::*};

pub struct AuxData<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub id_cred_base: P::G_1,
    // comm_1_params:  CommitmentParams<P::G_1>,
    pub ps_public_key:  ps_sig::PublicKey<P>,
    pub ps_secret_key:  ps_sig::SecretKey<P>,
    pub comm_2_params:  CommitmentParams<C>,
    pub elgamal_params: ElgamalParams<C>,
    pub ar_info:        ArInfo<C>,
}

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
    pre_id_obj: &PreIdentityObject<P, AttributeType, C>,
    aux_data: AuxData<P, C>,
) -> Result<ps_sig::Signature<P>, Declined> {
    let b_1 = verify_knowledge_of_id_cred_sec::<P::G_1>(
        &aux_data.id_cred_base,
        &pre_id_obj.id_cred_pub,
        &pre_id_obj.pok_sc,
    );
    if !b_1 {
        return Err(Declined(Reason::FailedToVerifyKnowledgeOfIdCredSec));
    }

    let comm_1_params =
        CommitmentParams((aux_data.ps_public_key.0[0], aux_data.ps_public_key.0[1]));
    let b_2 = verify_vrf_key_data(
        &comm_1_params,
        &pre_id_obj.cmm_prf,
        &aux_data.comm_2_params,
        &pre_id_obj.snd_cmm_prf,
        &aux_data.elgamal_params,
        &pre_id_obj.id_ar_data.e_reg_id,
        &pre_id_obj.proof_com_eq,
        &pre_id_obj.proof_com_enc_eq,
    );
    if !b_2 {
        return Err(Declined(Reason::FailedToVerifyPrfData));
    }
    let message: ps_sig::UnknownMessage<P> = compute_message(
        &pre_id_obj.id_cred_pub,
        &pre_id_obj.cmm_prf,
        &pre_id_obj.alist,
        &aux_data.ps_public_key,
    );
    let mut csprng = thread_rng();
    Ok(aux_data
        .ps_secret_key
        .sign_unknown_message(&message, &mut csprng))
}

fn compute_message<P: Pairing, AttributeType: Attribute<P::ScalarField>>(
    id_cred_pub: &elgamal::PublicKey<P::G_1>,
    cmm_prf: &PedersenCommitment<P::G_1>,
    att_list: &AttributeList<P::ScalarField, AttributeType>,
    ps_public_key: &ps_sig::PublicKey<P>,
) -> ps_sig::UnknownMessage<P> {
    let mut message = id_cred_pub.0;
    message = message.plus_point(&cmm_prf.0);
    let att_vec = &att_list.alist;
    let n = att_vec.len();
    let key_vec = &ps_public_key.0;
    assert!(key_vec.len() >= n + 2);
    for i in 2..(n + 2) {
        let att = att_vec[i - 2].to_field_element();
        message = message.plus_point(&key_vec[i].mul_by_scalar(&att))
    }

    ps_sig::UnknownMessage(message)
}

fn verify_knowledge_of_id_cred_sec<C: Curve>(
    base: &C,
    pk: &elgamal::PublicKey<C>,
    proof: &DlogProof<C>,
) -> bool {
    let public = pk.0;
    verify_dlog(base, &public, proof)
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
    let b_2 = verify_com_enc_eq(&coeff, &eval, comm_enc_eq_proof);
    if b_2 {
        true
    } else {
        false
    }
}
