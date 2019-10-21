use crate::types::*;

use sha2::{Digest, Sha512};

use core::fmt::{self, Display};
use curve_arithmetic::{Curve, Pairing};
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use elgamal::public::PublicKey;
use ff::Field;
use pedersen_scheme::{
    commitment::Commitment, key::CommitmentKey, randomness::Randomness, value::Value,
};
use ps_sig;

use sigma_protocols::{com_enc_eq, com_eq_sig, com_mult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDIVerificationError {
    RegId,
    IdCredPub,
    Signature,
    Dlog,
    Policy,
    AR,
}

impl Display for CDIVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CDIVerificationError::RegId => write!(f, "RegIdVerificationError"),
            CDIVerificationError::IdCredPub => write!(f, "IdCredPubVerificationError"),
            CDIVerificationError::Signature => write!(f, "SignatureVerificationError"),
            CDIVerificationError::Dlog => write!(f, "DlogVerificationError"),
            CDIVerificationError::Policy => write!(f, "PolicyVerificationError"),
            CDIVerificationError::AR => write!(f, "AnonimityRevokerVerificationError"),
        }
    }
}
/// verify credential deployment info
pub fn verify_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    global_context: &GlobalContext<C>,
    ip_info: &IpInfo<P, C>,
    cdi: &CredDeploymentInfo<P, C, AttributeType>,
) -> Result<(), CDIVerificationError> {
    // anonimity revokation data
    // preprocessing
    let ars = cdi.values.choice_ar_handles.clone();
    let ar_commitments = cdi.proofs.commitments.cmm_ars.clone();
    if ars.len() != ar_commitments.len() {
        return Err(CDIVerificationError::AR);
    }
    let mut choice_ar_parameters = Vec::with_capacity(ars.len());
    for handle in ars.into_iter() {
        // check that the handle is in the commitment list
        match ar_commitments.iter().find(|&x| {
            *x == global_context.on_chain_commitment_key.hide(
                &Value(C::scalar_from_u64(handle as u64).unwrap()),
                &Randomness(C::Scalar::zero()),
            )
        }) {
            None => return Err(CDIVerificationError::AR),
            Some(_) => match ip_info.ar_info.0.iter().find(|&x| x.ar_identity == handle) {
                None => return Err(CDIVerificationError::AR),
                Some(ar_info) => choice_ar_parameters.push(ar_info.clone()),
            },
        }
    }
    verify_cdi_worker(
        &global_context.on_chain_commitment_key,
        &ip_info.ip_verify_key,
        choice_ar_parameters,
        cdi,
    )
}

pub fn verify_cdi_worker<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    on_chain_commitment_key: &CommitmentKey<C>,
    ip_verify_key: &ps_sig::PublicKey<P>,
    choice_ar_parameters: Vec<ArInfo<C>>,
    cdi: &CredDeploymentInfo<P, C, AttributeType>,
) -> Result<(), CDIVerificationError> {
    // Compute the challenge prefix by hashing the values.
    let mut hasher = Sha512::new();
    hasher.input(&cdi.values.to_bytes());
    let challenge_prefix = hasher.result();

    let commitments = &cdi.proofs.commitments;
    // verify id_cred sharing data
    let check_id_cred_pub = verify_id_cred_pub_sharing_data(
        &challenge_prefix,
        on_chain_commitment_key,
        &choice_ar_parameters,
        &cdi.values.ar_data,
        &commitments.cmm_id_cred_sec_sharing_coeff,
        &cdi.proofs.proof_id_cred_pub,
    );
    if !check_id_cred_pub {
        return Err(CDIVerificationError::IdCredPub);
    }

    let check_reg_id = verify_pok_reg_id(
        &challenge_prefix,
        on_chain_commitment_key,
        &commitments.cmm_prf,
        &commitments.cmm_cred_counter,
        cdi.values.reg_id,
        &cdi.proofs.proof_reg_id,
    );

    if !check_reg_id {
        return Err(CDIVerificationError::RegId);
    }

    let verify_dlog = eddsa_dlog::verify_dlog_ed25519(
        &challenge_prefix,
        &cdi.values.acc_pub_key,
        &cdi.proofs.proof_acc_sk,
    );

    if !verify_dlog {
        return Err(CDIVerificationError::Dlog);
    }

    let check_pok_sig = verify_pok_sig(
        &challenge_prefix,
        on_chain_commitment_key,
        &commitments,
        ip_verify_key,
        &cdi.proofs.sig,
        &cdi.proofs.proof_ip_sig,
    );

    if !check_pok_sig {
        return Err(CDIVerificationError::Signature);
    }

    let check_policy = verify_policy(
        on_chain_commitment_key,
        &commitments,
        &cdi.values.policy,
        &cdi.proofs.proof_policy,
    );

    if !check_policy {
        return Err(CDIVerificationError::Policy);
    }
    Ok(())
}
/// verify id_cred data
fn verify_id_cred_pub_sharing_data<C: Curve>(
    challenge_prefix: &[u8],
    commitment_key: &CommitmentKey<C>,
    choice_ar_parameters: &[ArInfo<C>],
    chain_ar_data: &[ChainArData<C>],
    cmm_sharing_coeff: &[Commitment<C>],
    proof_id_cred_pub: &[(u64, com_enc_eq::ComEncEqProof<C>)],
) -> bool {
    let CommitmentKey(g_1, h_1) = commitment_key;
    // let cmm_to_shares = Vec::new();
    for ar in chain_ar_data.iter() {
        let cmm_share = commitment_to_share(ar.id_cred_pub_share_number, cmm_sharing_coeff);
        // finding the correct AR data by share number
        match proof_id_cred_pub
            .iter()
            .find(|&x| x.0 == ar.id_cred_pub_share_number)
        {
            None => {
                return false;
            }
            // finding the correct AR info
            Some((_, proof)) => match choice_ar_parameters
                .iter()
                .find(|&x| x.ar_identity == ar.ar_identity)
            {
                None => return false,
                Some(ar_info) => {
                    let (g, h) = (PublicKey::generator(), ar_info.ar_public_key.0);
                    let (e_1, e_2) = (ar.enc_id_cred_pub_share.0, ar.enc_id_cred_pub_share.1);
                    let coeff = (g, h, *g_1, *h_1);
                    let eval = (e_1, e_2, cmm_share.0);
                    // verifying the proof
                    if !com_enc_eq::verify_com_enc_eq(&challenge_prefix, &coeff, &eval, proof) {
                        return false;
                    }
                }
            },
        }
    }
    true
}
// computing the commitment to a single share from the commitments to the
// coefficients
#[inline(always)]
pub fn commitment_to_share<C: Curve>(
    share_number: u64,
    coeff_commitments: &[Commitment<C>],
) -> Commitment<C> {
    let mut cmm_share_point: C = coeff_commitments[0].0;
    for (i, Commitment(cmm_point)) in coeff_commitments.iter().enumerate().skip(1) {
        let j_pow_i: C::Scalar = C::scalar_from_u64(share_number as u64)
            .unwrap()
            .pow([i as u64]);
        let a = cmm_point.mul_by_scalar(&j_pow_i);
        cmm_share_point = cmm_share_point.plus_point(&a);
    }
    Commitment(cmm_share_point)
}

fn verify_policy<C: Curve, AttributeType: Attribute<C::Scalar>>(
    commitment_key: &CommitmentKey<C>,
    commitments: &CredDeploymentCommitments<C>,
    policy: &Policy<C, AttributeType>,
    policy_proof: &PolicyProof<C>,
) -> bool {
    let variant_scalar = C::scalar_from_u64(u64::from(policy.variant)).unwrap();
    let expiry_scalar = C::scalar_from_u64(policy.expiry).unwrap();

    let cmm_vec = &commitments.cmm_attributes;

    let b1 = commitment_key.open(
        &Value(variant_scalar),
        &Randomness(policy_proof.variant_rand),
        &cmm_vec[0],
    );
    if !b1 {
        return false;
    }
    let b2 = commitment_key.open(
        &Value(expiry_scalar),
        &Randomness(policy_proof.expiry_rand),
        &cmm_vec[1],
    );
    if !b2 {
        return false;
    }

    // NOTE: This is basic proof-of concept. The correct solution is to instead
    // check that both lists come in increasing order of idx. Then the check
    // will be linear in the number of items in the policy, as opposed to
    // quadratic as it is now.
    for (idx, v) in policy.policy_vec.iter() {
        if usize::from(idx + 2) < cmm_vec.len() {
            if let Some(pos) = policy_proof
                .cmm_opening_map
                .iter()
                .position(|idx_1| *idx == idx_1.0)
            {
                // found a randomness, now check opening
                if !commitment_key.open(
                    &Value(v.to_field_element()),
                    &Randomness(policy_proof.cmm_opening_map[pos].1),
                    &cmm_vec[usize::from(idx + 2)],
                ) {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

fn verify_pok_sig<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    challenge_prefix: &[u8],
    commitment_key: &CommitmentKey<C>,
    commitments: &CredDeploymentCommitments<C>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    blinded_sig: &ps_sig::Signature<P>,
    proof: &com_eq_sig::ComEqSigProof<P, C>,
) -> bool {
    let ps_sig::Signature(a, b) = blinded_sig;
    let (eval_pair, eval) = (b, P::G_2::one_point());
    let (g_base, h_base) = (commitment_key.0, commitment_key.1);
    let ps_sig::PublicKey(_gen1, _gen2, _, yxs, ip_pub_key_x) = ip_pub_key;

    let (p_pair, p) = (a, ip_pub_key_x);

    let (q_pair, q) = (a, P::G_2::one_point());

    // number of commitments in the attribute list
    // to these we add commitments to idcredsec and prf key K
    let user_cmm_atts_len = commitments.cmm_attributes.len();
    let user_cmm_ars_len = commitments.cmm_ars.len();

    let gxs = yxs[..user_cmm_atts_len + user_cmm_ars_len + 2].to_vec();

    let gxs_pair = a; // CHECK with Bassel

    let mut comm_vec = Vec::with_capacity(gxs.len());
    let cmm_id_cred_sec = commitments.cmm_id_cred_sec_sharing_coeff[0];
    comm_vec.push(cmm_id_cred_sec.0);
    comm_vec.push(commitments.cmm_prf.0);
    for v in commitments.cmm_attributes.iter() {
        comm_vec.push(v.0);
    }
    for ar in commitments.cmm_ars.iter() {
        comm_vec.push(ar.0);
    }
    com_eq_sig::verify_com_eq_sig::<P, C>(
        &challenge_prefix,
        &((*eval_pair, eval), comm_vec),
        &(
            (*p_pair, *p),
            (*q_pair, q),
            (*gxs_pair, gxs),
            (g_base, h_base),
        ),
        proof,
    )
}

fn verify_pok_reg_id<C: Curve>(
    challenge_prefix: &[u8],
    on_chain_commitment_key: &CommitmentKey<C>,
    cmm_prf: &Commitment<C>,
    cmm_cred_counter: &Commitment<C>,
    reg_id: C,
    proof: &com_mult::ComMultProof<C>,
) -> bool {
    // coefficients of the protocol derived from the pedersen key
    let g = on_chain_commitment_key.0;
    let h = on_chain_commitment_key.1;

    let coeff = [g, h];

    // commitments are the public values.
    let public = [cmm_prf.0.plus_point(&cmm_cred_counter.0), reg_id, g];

    com_mult::verify_com_mult(&challenge_prefix, &coeff, &public, &proof)
}
// fn verify_pok_id_cred_pub<C: Curve>(
// challenge_prefix: &[u8],
// on_chain_commitment_key: &PedersenKey<C>,
// ar_info_generator: &C,
// ar_info_public_key: &PublicKey<C>,
// id_cred_pub_enc: &Cipher<C>,
// cmm_id_cred_sec: &Commitment<C>,
// proof: &com_enc_eq::ComEncEqProof<C>,
// ) -> bool {
// let public = (id_cred_pub_enc.0, id_cred_pub_enc.1, cmm_id_cred_sec.0);
// FIXME: The one_point needs to be a parameter.
// let cmm_key = on_chain_commitment_key;
// let base = (
// ar_info_generator,
// ar_info_public_key.0,
// cmm_key.0[0],
// cmm_key.1,
// );
//
// com_enc_eq::verify_com_enc_eq::<C>(&challenge_prefix, &base, &public, proof)
// }
