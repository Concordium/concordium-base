use crate::types::*;

use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use elgamal::{cipher::Cipher, message::Message as ElgamalMessage};
use pairing::Field;
use pedersen_scheme::{
    commitment::Commitment,
    key::{CommitmentKey, CommitmentKey as PedersenKey},
    value as pedersen,
    value::Value,
};
use ps_sig;
use rand::*;
use sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult, dlog};
use core::fmt::{self, Display};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDIVerificationError {
    RegId,
    IdCredPub,
    Signature,
    Dlog
}

impl Display for CDIVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CDIVerificationError::RegId => write!(f, "RegIdVerificationError"),
            CDIVerificationError::IdCredPub => write!(f, "IdCredPubVerificationError"),
            CDIVerificationError::Signature => write!(f, "SignatureVerificationError"),
            CDIVerificationError::Dlog => write!(f, "DlogVerificationError"),
        }
    }
}

pub fn verify_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
>(
    global_context: &GlobalContext<C>,
    ip_info: IpInfo<P, C>,
    cdi: CredDeploymentInfo<P, C>,
) -> Result<(), CDIVerificationError> {
    let commitments = cdi.commitments;
    let check_id_cred_pub = verify_pok_id_cred_pub(
        &global_context,
        &ip_info.ar_info,
        &cdi.ar_data.id_cred_pub_enc,
        &commitments.cmm_id_cred_sec,
        &cdi.proofs.proof_id_cred_pub,
    );
    if !check_id_cred_pub {
        return Err(CDIVerificationError::IdCredPub)
    }

    let check_reg_id = verify_pok_reg_id(
        &global_context.on_chain_commitment_key,
        &commitments.cmm_prf,
        &commitments.cmm_cred_counter,
        cdi.reg_id,
        &cdi.proofs.proof_reg_id,
    );

    if !check_reg_id {
        return Err(CDIVerificationError::RegId)
    }

    let challenge_prefix = [0; 32];
    let verify_dlog = eddsa_dlog::verify_dlog_ed25519(
        &challenge_prefix,
        &cdi.acc_pub_key,
        &cdi.proofs.proof_acc_sk,
    );

    if !verify_dlog {
        return Err(CDIVerificationError::Dlog)
    }

    let check_pok_sig = verify_pok_sig(
        &global_context.on_chain_commitment_key,
        &commitments,
        &ip_info.ip_verify_key,
        &cdi.sig,
        &cdi.proofs.proof_ip_sig,
    );

    if !check_pok_sig {
        return Err(CDIVerificationError::Signature)
    }

    // TODO: Check commitment openings.

    Ok(())
}

fn verify_pok_sig<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    commitment_key: &PedersenKey<C>,
    commitments: &CredDeploymentCommitments<C>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    blinded_sig: &ps_sig::Signature<P>,
    proof: &com_eq_sig::ComEqSigProof<P, C>,
) -> bool {
    let ps_sig::Signature(a, b) = blinded_sig;
    let (eval_pair, eval) = (b, P::G_2::one_point());
    let (g, h) = ((commitment_key.0)[0], commitment_key.1);
    let ps_sig::PublicKey(_gen1, _gen2, _, yxs, x) = ip_pub_key;

    let (p_pair, p) = (a, x);

    let (q_pair, q) = (a, P::G_2::one_point());

    let n = commitments.cmm_attributes.len();

    let gxs = yxs[..n+2].to_vec();

    let challenge_prefix = [0; 32];

    let gxs_pair = a; // CHECK with Bassel

    let mut comm_vec = Vec::with_capacity(gxs.len());
    comm_vec.push(commitments.cmm_id_cred_sec.0);
    comm_vec.push(commitments.cmm_prf.0);
    for v in commitments.cmm_attributes.iter() {
        comm_vec.push(v.0);
    }
    com_eq_sig::verify_com_eq_sig::<P, C>(
        &challenge_prefix,
        &((*eval_pair, eval), comm_vec),
        &((*p_pair, *p), (*q_pair, q), (*gxs_pair, gxs), (g, h)),
        proof,
    )
}

fn verify_pok_reg_id<C: Curve>(
    on_chain_commitment_key: &PedersenKey<C>,
    cmm_prf: &Commitment<C>,
    cmm_cred_counter: &Commitment<C>,
    reg_id: C,
    proof: &com_mult::ComMultProof<C>,
) -> bool {
    // coefficients of the protocol derived from the pedersen key
    let g = on_chain_commitment_key.0[0];
    let h = on_chain_commitment_key.1;

    let coeff = [g, h];

    // commitments are the public values.
    let public = [cmm_prf.0.plus_point(&cmm_cred_counter.0), reg_id, g];

    let challenge_prefix = [0; 32]; // FIXME

    com_mult::verify_com_mult(&challenge_prefix, &coeff, &public, &proof)
}

fn verify_pok_id_cred_pub<C: Curve>(
    global_context: &GlobalContext<C>,
    ar_info: &ArInfo<C>,
    id_cred_pub_enc: &Cipher<C>,
    cmm_id_cred_sec: &Commitment<C>,
    proof: &com_enc_eq::ComEncEqProof<C>,
) -> bool {
    // FIXME
    let challenge_prefix = [0; 32];

    let public = (id_cred_pub_enc.0, id_cred_pub_enc.1, cmm_id_cred_sec.0);
    // FIXME: The one_point needs to be a parameter.
    let cmm_key = &global_context.on_chain_commitment_key;
    let base = (
        ar_info.ar_elgamal_generator,
        ar_info.ar_public_key.0,
        cmm_key.0[0],
        cmm_key.1,
    );

    com_enc_eq::verify_com_enc_eq::<C>(&challenge_prefix, &base, &public, proof)
}
