use random_oracle::RandomOracle;

use crate::{
    secret_sharing::{ShareNumber, Threshold},
    types::*,
};
use core::fmt::{self, Display};
use curve_arithmetic::{Curve, Pairing};
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use pedersen_scheme::{
    commitment::Commitment, key::CommitmentKey, randomness::Randomness, value::Value,
};
use ps_sig;
use std::collections::BTreeSet;

use either::Either;

use crate::sigma_protocols::{com_enc_eq, com_eq_sig, com_mult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDIVerificationError {
    RegId,
    IdCredPub,
    Signature,
    Dlog,
    AccountOwnership,
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
            CDIVerificationError::AccountOwnership => write!(f, "AccountOwnership"),
            CDIVerificationError::Policy => write!(f, "PolicyVerificationError"),
            CDIVerificationError::AR => write!(f, "AnonymityRevokerVerificationError"),
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
    acc_keys: Option<&AccountKeys>,
    cdi: &CredDeploymentInfo<P, C, AttributeType>,
) -> Result<(), CDIVerificationError> {
    // anonimity revocation data
    // preprocessing
    let ars = &cdi
        .values
        .ar_data
        .iter()
        .map(|x| x.ar_identity)
        .collect::<Vec<ArIdentity>>();

    let mut choice_ar_parameters = Vec::with_capacity(ars.len());

    // find ArInfo's corresponding to this credential in the
    // IpInfo.
    // FIXME: This is quadratic due to the choice of data structures.
    // We could likely have a map in IPInfo instead of a list.
    for &handle in ars.iter() {
        match ip_info.ip_ars.ars.iter().find(|&x| x.ar_identity == handle) {
            None => return Err(CDIVerificationError::AR),
            Some(ar_info) => choice_ar_parameters.push(ar_info),
        }
    }
    verify_cdi_worker(
        &global_context.on_chain_commitment_key,
        &ip_info.ip_verify_key,
        &choice_ar_parameters,
        acc_keys,
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
    choice_ar_parameters: &[&ArInfo<C>],
    acc_keys: Option<&AccountKeys>,
    cdi: &CredDeploymentInfo<P, C, AttributeType>,
) -> Result<(), CDIVerificationError> {
    // Compute the challenge prefix by hashing the values.
    let ro = RandomOracle::domain("credential").append(&cdi.values);

    let commitments = &cdi.proofs.commitments;
    // verify id_cred sharing data
    let check_id_cred_pub = verify_id_cred_pub_sharing_data(
        ro.split(),
        on_chain_commitment_key,
        choice_ar_parameters,
        &cdi.values.ar_data,
        &commitments.cmm_id_cred_sec_sharing_coeff,
        &cdi.proofs.proof_id_cred_pub,
    );
    if !check_id_cred_pub {
        return Err(CDIVerificationError::IdCredPub);
    }

    let check_reg_id = verify_pok_reg_id(
        ro.split(),
        on_chain_commitment_key,
        &commitments.cmm_prf,
        &commitments.cmm_cred_counter,
        cdi.values.reg_id,
        &cdi.proofs.proof_reg_id,
    );

    if !check_reg_id {
        return Err(CDIVerificationError::RegId);
    }

    let cdv = &cdi.values;
    let proofs = &cdi.proofs;

    match cdv.cred_account {
        CredentialAccount::ExistingAccount(_addr) => {
            // in this case we must have been given the account keys.
            if let Some(acc_keys) = acc_keys {
                if proofs.proof_acc_sk.num_proofs() < acc_keys.threshold {
                    return Err(CDIVerificationError::AccountOwnership);
                }
                // we at least have enough proofs now, if they are all valid and have valid
                // indices
                for (&idx, proof) in proofs.proof_acc_sk.proofs.iter() {
                    if let Some(key) = acc_keys.get(idx) {
                        let VerifyKey::Ed25519VerifyKey(ref key) = key;
                        let verify_dlog = eddsa_dlog::verify_dlog_ed25519(ro.split(), key, proof);
                        if !verify_dlog {
                            return Err(CDIVerificationError::AccountOwnership);
                        }
                    } else {
                        return Err(CDIVerificationError::AccountOwnership);
                    }
                }
            } else {
                // in case of an existing account we must have been given account keys
                return Err(CDIVerificationError::AccountOwnership);
            }
        }
        CredentialAccount::NewAccount(ref keys, threshold) => {
            // we check all the keys that were provided, and check enough were provided
            // compared to the threshold
            // We also make sure that no more than 255 keys are provided, as well as
            // - all keys are distinct
            // - at least one key is provided
            // - there are the same number of proofs and keys
            if proofs.proof_acc_sk.num_proofs() < threshold
                || keys.len() > 255
                || keys.is_empty()
                || proofs.proof_acc_sk.num_proofs() != SignatureThreshold(keys.len() as u8)
            {
                return Err(CDIVerificationError::AccountOwnership);
            }
            // set of processed keys already
            let mut processed = BTreeSet::new();
            // the new keys get indices 0, 1, ..
            for (idx, key) in (0u8..).zip(keys.iter()) {
                let idx = KeyIndex(idx);
                // insert returns true if key was __not__ present
                if !processed.insert(key) {
                    return Err(CDIVerificationError::AccountOwnership);
                }
                if let Some(proof) = proofs.proof_acc_sk.proofs.get(&idx) {
                    let VerifyKey::Ed25519VerifyKey(ref key) = key;
                    let verify_dlog = eddsa_dlog::verify_dlog_ed25519(ro.split(), key, proof);
                    if !verify_dlog {
                        return Err(CDIVerificationError::AccountOwnership);
                    }
                } else {
                    return Err(CDIVerificationError::AccountOwnership);
                }
            }
        }
    };

    let check_pok_sig = verify_pok_sig(
        ro,
        on_chain_commitment_key,
        cdi.values.threshold,
        choice_ar_parameters,
        &cdi.values.policy,
        &commitments,
        ip_verify_key,
        &cdi.proofs.sig,
        &cdi.proofs.proof_ip_sig,
    );

    if !check_pok_sig {
        return Err(CDIVerificationError::Signature);
    }

    let check_policy = verify_policy(on_chain_commitment_key, &commitments, &cdi.values.policy);

    if !check_policy {
        return Err(CDIVerificationError::Policy);
    }
    Ok(())
}
/// verify id_cred data
fn verify_id_cred_pub_sharing_data<C: Curve>(
    ro: RandomOracle,
    commitment_key: &CommitmentKey<C>,
    choice_ar_parameters: &[&ArInfo<C>],
    chain_ar_data: &[ChainArData<C>],
    cmm_sharing_coeff: &[Commitment<C>],
    proof_id_cred_pub: &[(ShareNumber, com_enc_eq::ComEncEqProof<C>)],
) -> bool {
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
                    // verifying the proof
                    if !com_enc_eq::verify_com_enc_eq(
                        ro.split(),
                        &ar.enc_id_cred_pub_share,
                        &cmm_share,
                        &ar_info.ar_public_key,
                        commitment_key,
                        proof,
                    ) {
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
pub fn commitment_to_share<C: Curve>(
    share_number: ShareNumber,
    coeff_commitments: &[Commitment<C>],
) -> Commitment<C> {
    let mut cmm_share_point: C = C::zero_point();
    let share_scalar = share_number.to_scalar::<C>();
    // Essentially Horner's scheme in the exponent.
    // Likely this would be better done with multiexponentiation,
    // although this is not clear.
    for cmm in coeff_commitments.iter().rev() {
        cmm_share_point = cmm_share_point.mul_by_scalar(&share_scalar);
        cmm_share_point = cmm_share_point.plus_point(&cmm);
    }
    Commitment(cmm_share_point)
}

/// Verify a policy. This currently does not do anything since
/// the only check that is done is that the commitments are opened correctly,
/// and that check is part of the signature check.
fn verify_policy<C: Curve, AttributeType: Attribute<C::Scalar>>(
    _commitment_key: &CommitmentKey<C>,
    _commitments: &CredDeploymentCommitments<C>,
    _policy: &Policy<C, AttributeType>,
) -> bool {
    // let variant_scalar = C::scalar_from_u64(u64::from(policy.variant)).unwrap();
    // let expiry_scalar = C::scalar_from_u64(policy.expiry).unwrap();

    // let cmm_vec = &commitments.cmm_attributes;

    // let b1 = commitment_key.open(
    //     &Value {
    //         value: variant_scalar,
    //     },
    //     &policy_proof.variant_rand,
    //     &cmm_vec[0],
    // );
    // if !b1 {
    //     return false;
    // }
    // let b2 = commitment_key.open(
    //     &Value {
    //         value: expiry_scalar,
    //     },
    //     &policy_proof.expiry_rand,
    //     &cmm_vec[1],
    // );
    // if !b2 {
    //     return false;
    // }

    // // NOTE: This is basic proof-of concept. The correct solution is to instead
    // // check that both lists come in increasing order of idx. Then the check
    // // will be linear in the number of items in the policy, as opposed to
    // // quadratic as it is now.
    // for (idx, v) in policy.policy_vec.iter() {
    //     if usize::from(idx + 2) < cmm_vec.len() {
    //         if let Some(pos) = policy_proof
    //             .cmm_opening_map
    //             .iter()
    //             .position(|idx_1| *idx == idx_1.0)
    //         {
    //             // found a randomness, now check opening
    //             if !commitment_key.open(
    //                 &Value {
    //                     value: v.to_field_element(),
    //                 },
    //                 &policy_proof.cmm_opening_map[pos].1,
    //                 &cmm_vec[usize::from(idx + 2)],
    //             ) {
    //                 return false;
    //             }
    //         } else {
    //             return false;
    //         }
    //     } else {
    //         return false;
    //     }
    // }
    true
}

#[allow(clippy::too_many_arguments)]
fn verify_pok_sig<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
>(
    ro: RandomOracle,
    commitment_key: &CommitmentKey<C>,
    threshold: Threshold,
    choice_ar_parameters: &[&ArInfo<C>],
    policy: &Policy<C, AttributeType>,
    commitments: &CredDeploymentCommitments<C>,
    ip_pub_key: &ps_sig::PublicKey<P>,
    blinded_sig: &ps_sig::BlindedSignature<P>,
    proof: &com_eq_sig::ComEqSigProof<P, C>,
) -> bool {
    let mut comm_vec =
        Vec::with_capacity(2 + 1 + choice_ar_parameters.len() + commitments.cmm_attributes.len());
    let cmm_id_cred_sec = commitments.cmm_id_cred_sec_sharing_coeff[0];
    comm_vec.push(cmm_id_cred_sec);
    comm_vec.push(commitments.cmm_prf);

    // compute commitments with randomness 0
    let zero = Randomness::zero();
    // add commitment to threshold with randomness 0
    comm_vec.push(commitment_key.hide(&Value::new(threshold.to_scalar::<C>()), &zero));
    // and all commitments to ARs with randomness 0
    for ar in choice_ar_parameters {
        comm_vec.push(commitment_key.hide(&Value::new(ar.ar_identity.to_scalar::<C>()), &zero));
    }

    let tags = {
        match encode_tags(
            policy
                .policy_vec
                .keys()
                .chain(commitments.cmm_attributes.keys()),
        ) {
            Ok(v) => v,
            Err(_) => return false,
        }
    };

    // add commitment with randomness 0 for variant and expiry of
    // the attribute list
    comm_vec.push(commitment_key.hide(&Value::new(tags), &zero));
    comm_vec.push(commitment_key.hide(&Value::new(C::scalar_from_u64(policy.expiry)), &zero));

    // now, we go through the policy and remaining commitments and
    // put them into the vector of commitments in order to check the signature.
    // NB: It is crucial that they are put into the vector ordered by tags, since
    // otherwise the signature will not check out.
    // At this point we know all tags are distinct.

    let f = |v: Either<&AttributeType, &Commitment<_>>| match v {
        Either::Left(v) => {
            let value = Value::new(v.to_field_element());
            comm_vec.push(commitment_key.hide(&value, &zero));
        }
        Either::Right(v) => {
            comm_vec.push(*v);
        }
    };

    merge_iter(
        policy.policy_vec.iter(),
        commitments.cmm_attributes.iter(),
        f,
    );

    com_eq_sig::verify_com_eq_sig::<P, C>(
        ro,
        blinded_sig,
        &comm_vec,
        ip_pub_key,
        commitment_key,
        proof,
    )
}

fn verify_pok_reg_id<C: Curve>(
    ro: RandomOracle,
    on_chain_commitment_key: &CommitmentKey<C>,
    cmm_prf: &Commitment<C>,
    cmm_cred_counter: &Commitment<C>,
    reg_id: C,
    proof: &com_mult::ComMultProof<C>,
) -> bool {
    // coefficients of the protocol derived from the pedersen key
    let g = on_chain_commitment_key.0;

    // commitments are the public values.
    // NOTE: In order for this to work the reg_id must be computed with the same
    // generator as the first element of the on-chain commitment key

    com_mult::verify_com_mult(
        ro,
        &cmm_prf.combine(&cmm_cred_counter),
        &Commitment(reg_id),
        &Commitment(g),
        on_chain_commitment_key,
        &proof,
    )
}
