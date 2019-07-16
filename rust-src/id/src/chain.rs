use crate::types::*;

use sha2::{Digest, Sha512};

use core::fmt::{self, Display};
use curve_arithmetic::{Curve, Pairing};
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use elgamal::{cipher::Cipher, public::PublicKey};
use pedersen_scheme::{commitment::Commitment, key::CommitmentKey as PedersenKey, value::Value};
use ps_sig;

use sigma_protocols::{com_enc_eq, com_eq_sig, com_mult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDIVerificationError {
    RegId,
    IdCredPub,
    Signature,
    Dlog,
    Policy,
}

impl Display for CDIVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CDIVerificationError::RegId => write!(f, "RegIdVerificationError"),
            CDIVerificationError::IdCredPub => write!(f, "IdCredPubVerificationError"),
            CDIVerificationError::Signature => write!(f, "SignatureVerificationError"),
            CDIVerificationError::Dlog => write!(f, "DlogVerificationError"),
            CDIVerificationError::Policy => write!(f, "PolicyVerificationError"),
        }
    }
}

pub fn verify_cdi<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    global_context: &GlobalContext<C>,
    ip_info: &IpInfo<P, C>,
    cdi: CredDeploymentInfo<P, C, AttributeType>,
) -> Result<(), CDIVerificationError> {
    verify_cdi_worker(
        &global_context.on_chain_commitment_key,
        &ip_info.ar_info.ar_elgamal_generator,
        &ip_info.ar_info.ar_public_key,
        &ip_info.ip_verify_key,
        cdi,
    )
}

pub fn verify_cdi_worker<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    on_chain_commitment_key: &PedersenKey<C>,
    ar_info_generator: &C,
    ar_info_public_key: &PublicKey<C>,
    ip_verify_key: &ps_sig::PublicKey<P>,
    cdi: CredDeploymentInfo<P, C, AttributeType>,
) -> Result<(), CDIVerificationError> {
    // Compute the challenge prefix by hashing the values.
    let mut hasher = Sha512::new();
    hasher.input(&cdi.values.to_bytes());
    let challenge_prefix = hasher.result();

    let commitments = cdi.proofs.commitments;
    let check_id_cred_pub = verify_pok_id_cred_pub(
        &challenge_prefix,
        on_chain_commitment_key,
        ar_info_generator,
        ar_info_public_key,
        &cdi.values.ar_data.id_cred_pub_enc,
        &commitments.cmm_id_cred_sec,
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

fn verify_policy<C: Curve, AttributeType: Attribute<C::Scalar>>(
    commitment_key: &PedersenKey<C>,
    commitments: &CredDeploymentCommitments<C>,
    policy: &Policy<C, AttributeType>,
    policy_proof: &PolicyProof<C>,
) -> bool {
    let variant_scalar = C::scalar_from_u64(u64::from(policy.variant)).unwrap();
    let expiry_scalar = C::scalar_from_u64(policy.expiry).unwrap();

    let cmm_vec = &commitments.cmm_attributes;

    let b1 = commitment_key.open(
        &Value(vec![variant_scalar]),
        &policy_proof.variant_rand,
        &cmm_vec[0],
    );
    if !b1 {
        return false;
    }
    let b2 = commitment_key.open(
        &Value(vec![expiry_scalar]),
        &policy_proof.expiry_rand,
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
                    &Value(vec![v.to_field_element()]),
                    &policy_proof.cmm_opening_map[pos].1,
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

    let gxs = yxs[..n + 2].to_vec();

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
    challenge_prefix: &[u8],
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

    com_mult::verify_com_mult(&challenge_prefix, &coeff, &public, &proof)
}

fn verify_pok_id_cred_pub<C: Curve>(
    challenge_prefix: &[u8],
    on_chain_commitment_key: &PedersenKey<C>,
    ar_info_generator: &C,
    ar_info_public_key: &PublicKey<C>,
    id_cred_pub_enc: &Cipher<C>,
    cmm_id_cred_sec: &Commitment<C>,
    proof: &com_enc_eq::ComEncEqProof<C>,
) -> bool {
    let public = (id_cred_pub_enc.0, id_cred_pub_enc.1, cmm_id_cred_sec.0);
    // FIXME: The one_point needs to be a parameter.
    let cmm_key = on_chain_commitment_key;
    let base = (
        *ar_info_generator,
        ar_info_public_key.0,
        cmm_key.0[0],
        cmm_key.1,
    );

    com_enc_eq::verify_com_enc_eq::<C>(&challenge_prefix, &base, &public, proof)
}
