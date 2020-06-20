use crate::{
    secret_sharing::{ShareNumber, Threshold},
    sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups, common::*, dlog},
    types::*,
};
use curve_arithmetic::{Curve, Pairing};
use pedersen_scheme::{commitment::Commitment, key::CommitmentKey};

use random_oracle::RandomOracle;

use ff::Field;
use rand::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    FailedToVerifyKnowledgeOfIdCredSec,
    FailedToVerifyIdCredSecEquality,
    FailedToVerifyPrfData,
    WrongArParameters,
    IllegalAttributeRequirements,
    TooManyAttributes,
    IncorrectProof,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Reason::*;
        match *self {
            FailedToVerifyKnowledgeOfIdCredSec => {
                write!(f, "Cannot verify knowledge of idCredSec.")
            }
            FailedToVerifyIdCredSecEquality => write!(f, "Cannot verify consistency of idCredSec."),
            FailedToVerifyPrfData => write!(f, "Cannot verify consistency of PRF data."),
            WrongArParameters => write!(f, "Inconsistent anonymity revocation parameters."),
            IllegalAttributeRequirements => write!(f, "Illegal attributes."),
            TooManyAttributes => write!(f, "Too many attributes for the given public key."),
            IncorrectProof => write!(f, "Zero knowledge proof does not verify."),
        }
    }
}

fn check_ar_parameters<C: Curve>(
    _choice_ar_parameters: &(Vec<ArInfo<C>>, Threshold),
    _ip_ar_info: &[ArInfo<C>],
) -> bool {
    // some business logic here
    true
}

/// Validate all the proofs in an identity object request.
pub fn validate_request<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
    pre_id_obj: &PreIdentityObject<P, C>,
    ip_info: &IpInfo<P, C>,
) -> Result<(), Reason> {
    let commitment_key_sc = CommitmentKey(ip_info.ip_verify_key.ys[0], ip_info.ip_verify_key.g);
    let commitment_key_prf = CommitmentKey(ip_info.ip_verify_key.ys[1], ip_info.ip_verify_key.g);

    let ro = RandomOracle::empty();

    let id_cred_sec_verifier = dlog::Dlog {
        public: pre_id_obj.id_cred_pub,
        coeff:  ip_info.ip_ars.ar_base,
    };
    let id_cred_sec_witness = pre_id_obj.poks.id_cred_sec_witness;

    // Verify that id_cred_sec is the same both in id_cred_pub and in cmm_sc
    let id_cred_sec_eq_verifier = com_eq::ComEq {
        commitment: pre_id_obj.cmm_sc,
        y:          pre_id_obj.id_cred_pub,
        cmm_key:    commitment_key_sc,
        g:          ip_info.ip_ars.ar_base,
    };

    // TODO: Figure out whether we can somehow get rid of this clone.
    let id_cred_sec_eq_witness = pre_id_obj.poks.commitments_same_proof.clone();

    let choice_ar_handles = pre_id_obj.choice_ar_parameters.ar_identities.clone();
    let revocation_threshold = pre_id_obj.choice_ar_parameters.threshold;

    let number_of_ars = choice_ar_handles.len();
    let mut choice_ars = Vec::with_capacity(number_of_ars);
    for ar in choice_ar_handles.iter() {
        match ip_info.ip_ars.ars.iter().find(|&x| x.ar_identity == *ar) {
            None => return Err(Reason::WrongArParameters),
            Some(ar_info) => choice_ars.push(ar_info.clone()),
        }
    }

    // VRF
    let choice_ar_parameters = (choice_ars, revocation_threshold);
    if !check_ar_parameters(&choice_ar_parameters, &ip_info.ip_ars.ars) {
        return Err(Reason::WrongArParameters);
    }
    // ar commitment key
    let ar_ck = ip_info.ip_ars.ar_cmm_key;

    // The commitment to the PRF key to the identity providers
    // must have at least one value.
    // FIXME: Rework the choice of data-structure so that this is implicit.
    if pre_id_obj.cmm_prf_sharing_coeff.is_empty() {
        return Err(Reason::WrongArParameters);
    }

    // Verify that the two commitments to the PRF key are the same.
    let verifier_prf_same = com_eq_different_groups::ComEqDiffGroups {
        commitment_1: pre_id_obj.cmm_prf,
        commitment_2: *pre_id_obj
            .cmm_prf_sharing_coeff
            .first()
            .expect("Precondition checked."),
        cmm_key_1:    commitment_key_prf,
        cmm_key_2:    ar_ck,
    };
    let witness_prf_same = pre_id_obj.poks.commitments_prf_same;

    let prf_verification = compute_prf_sharing_verifier(
        &ar_ck,
        &pre_id_obj.cmm_prf_sharing_coeff,
        &pre_id_obj.ip_ar_data,
        &choice_ar_parameters.0,
    );
    let (prf_sharing_verifier, prf_sharing_witness) = match prf_verification {
        Some(v) => v,
        None => return Err(Reason::WrongArParameters),
    };

    let verifier = AndAdapter {
        first:  id_cred_sec_verifier,
        second: id_cred_sec_eq_verifier,
    };
    let verifier = verifier
        .add_prover(verifier_prf_same)
        .add_prover(prf_sharing_verifier);
    let witness = AndWitness {
        w1: AndWitness {
            w1: AndWitness {
                w1: id_cred_sec_witness,
                w2: id_cred_sec_eq_witness,
            },
            w2: witness_prf_same,
        },
        w2: prf_sharing_witness,
    };
    let proof = SigmaProof {
        challenge: pre_id_obj.poks.challenge,
        witness,
    };
    if verify(ro, &verifier, &proof) {
        Ok(())
    } else {
        Err(Reason::IncorrectProof)
    }
}

pub fn sign_identity_object<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObject<P, C>,
    ip_info: &IpInfo<P, C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Reason> {
    let choice_ar_handles = pre_id_obj.choice_ar_parameters.ar_identities.clone();
    let message: ps_sig::UnknownMessage<P> = compute_message(
        &pre_id_obj.cmm_prf,
        &pre_id_obj.cmm_sc,
        pre_id_obj.choice_ar_parameters.threshold,
        &choice_ar_handles,
        &alist,
        &ip_info.ip_verify_key,
    )?;
    let mut csprng = thread_rng();
    // FIXME: Pass in csprng here.
    Ok(ip_secret_key.sign_unknown_message(&message, &mut csprng))
}

fn compute_prf_sharing_verifier<'a, C: Curve>(
    ar_commitment_key: &'a CommitmentKey<C>,
    cmm_sharing_coeff: &'a [Commitment<C>],
    ip_ar_data: &'a [IpArData<C>],
    choice_ar_parameters: &'a [ArInfo<C>],
) -> Option<(
    ReplicateAdapter<com_enc_eq::ComEncEq<C>>,
    ReplicateWitness<com_enc_eq::Witness<C>>,
)> {
    let mut verifiers = Vec::with_capacity(ip_ar_data.len());
    let mut witnesses = Vec::with_capacity(ip_ar_data.len());

    for ar in ip_ar_data.iter() {
        let cmm_share = commitment_to_share(ar.prf_key_share_number, cmm_sharing_coeff);
        // finding the right encryption key
        match choice_ar_parameters
            .iter()
            .find(|&x| x.ar_identity == ar.ar_identity)
        {
            None => return None,
            Some(ar_info) => {
                let verifier = com_enc_eq::ComEncEq {
                    cipher:     ar.enc_prf_key_share,
                    commitment: cmm_share,
                    pub_key:    ar_info.ar_public_key,
                    cmm_key:    *ar_commitment_key,
                };
                verifiers.push(verifier);
                // TODO: Figure out whether we can somehow get rid of this clone.
                witnesses.push(ar.proof_com_enc_eq.clone());
            }
        }
    }
    Some((
        ReplicateAdapter {
            protocols: verifiers,
        },
        ReplicateWitness { witnesses },
    ))
}

/// Validate the request and sign the identity object.
pub fn verify_credentials<
    P: Pairing,
    AttributeType: Attribute<P::ScalarField>,
    C: Curve<Scalar = P::ScalarField>,
>(
    pre_id_obj: &PreIdentityObject<P, C>,
    ip_info: &IpInfo<P, C>,
    alist: &AttributeList<C::Scalar, AttributeType>,
    ip_secret_key: &ps_sig::SecretKey<P>,
) -> Result<ps_sig::Signature<P>, Reason> {
    validate_request(pre_id_obj, ip_info)?;

    sign_identity_object(pre_id_obj, ip_info, alist, ip_secret_key)
}

fn compute_message<P: Pairing, AttributeType: Attribute<P::ScalarField>>(
    cmm_prf: &Commitment<P::G1>,
    cmm_sc: &Commitment<P::G1>,
    threshold: Threshold,
    ar_list: &[ArIdentity],
    att_list: &AttributeList<P::ScalarField, AttributeType>,
    ps_public_key: &ps_sig::PublicKey<P>,
) -> Result<ps_sig::UnknownMessage<P>, Reason> {
    let valid_to = P::G1::scalar_from_u64(att_list.valid_to.into());
    let created_at = P::G1::scalar_from_u64(att_list.created_at.into());
    let max_accounts = P::G1::scalar_from_u64(att_list.max_accounts.into());

    let tags = {
        match encode_tags(att_list.alist.keys()) {
            Ok(f) => f,
            Err(_) => return Err(Reason::IllegalAttributeRequirements),
        }
    };

    // the list to be signed consists of (in that order)
    // - commitment to idcredsec
    // - commitment to prf key
    // - anonymity revocation threshold
    // - list of anonymity revokers
    // - tags of the attribute list
    // - valid_to date of the attribute list
    // - created_at of the attribute list
    // - attribute list elements

    let mut message = cmm_sc.0;
    message = message.plus_point(&cmm_prf.0);
    let att_vec = &att_list.alist;
    let m = ar_list.len();
    let n = att_vec.len();
    let key_vec = &ps_public_key.ys;

    if key_vec.len() < n + m + 7 {
        return Err(Reason::TooManyAttributes);
    }

    // add threshold to the message
    message = message.plus_point(&key_vec[2].mul_by_scalar(&threshold.to_scalar::<P::G1>()));
    // and add all anonymity revocation
    for i in 3..(m + 3) {
        let ar_handle = ar_list[i - 3].to_scalar::<P::G1>();
        message = message.plus_point(&key_vec[i].mul_by_scalar(&ar_handle));
    }

    message = message.plus_point(&key_vec[m + 3].mul_by_scalar(&tags));
    message = message.plus_point(&key_vec[m + 3 + 1].mul_by_scalar(&valid_to));
    message = message.plus_point(&key_vec[m + 3 + 2].mul_by_scalar(&created_at));
    message = message.plus_point(&key_vec[m + 3 + 3].mul_by_scalar(&max_accounts));
    // NB: It is crucial that att_vec is an ordered map and that .values iterator
    // returns messages in order of tags.
    for (k, v) in key_vec.iter().skip(m + 7).zip(att_vec.values()) {
        let att = v.to_field_element();
        message = message.plus_point(&k.mul_by_scalar(&att));
    }
    let msg = ps_sig::UnknownMessage(message);
    Ok(msg)
}

/// Given a list of commitments g^{a_i}h^{r_i}
/// and a point x (the share number), compute
/// g^p(x)h^r(x) where
/// p(x) = a_0 + a_1 x + ... + a_n x^n
/// r(x) = r_0 + r_1 x + ... + r_n x^n
pub fn commitment_to_share<C: Curve>(
    share_number: ShareNumber,
    coeff_commitments: &[Commitment<C>],
) -> Commitment<C> {
    // TODO: This would benefit from multiexponentiation.
    let mut cmm_share_point: C = coeff_commitments[0].0;
    for (i, Commitment(cmm_point)) in coeff_commitments.iter().enumerate().skip(1) {
        let j_pow_i: C::Scalar = share_number.to_scalar::<C>().pow([i as u64]);
        let a = cmm_point.mul_by_scalar(&j_pow_i);
        cmm_share_point = cmm_share_point.plus_point(&a);
    }
    Commitment(cmm_share_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::*;

    use pairing::bls12_381::G1;
    use pedersen_scheme::{key::CommitmentKey, Randomness, Value as PedersenValue};

    type ExampleCurve = G1;

    // Eval a polynomial at point.
    fn eval_poly<F: Field>(coeffs: &[F], x: &F) -> F {
        let mut acc = F::zero();
        for coeff in coeffs.iter().rev() {
            acc.mul_assign(x);
            acc.add_assign(coeff);
        }
        acc
    }

    /// Randomized test that commitment_to_share conforms to the specification.
    #[test]
    fn test_commitment_to_share() {
        let mut csprng = thread_rng();
        let ck = CommitmentKey::<G1>::generate(&mut csprng);

        // Make degree-d polynomial
        let d = csprng.gen_range(1, 10);
        let mut coeffs = Vec::new();
        let mut rands = Vec::new();
        let mut values = Vec::new();
        for _i in 0..=d {
            // Make commitments to coefficients
            let a = G1::generate_scalar(&mut csprng);
            let v = PedersenValue::from_scalar(a);
            let (c, r) = ck.commit(&v, &mut csprng);
            coeffs.push(c);
            rands.push(r.randomness);
            values.push(a);
        }

        // Sample some random share numbers
        for _ in 0..100 {
            let sh = ShareNumber::from(csprng.next_u32());
            // And evaluate the values and rands at sh.
            let point = ExampleCurve::scalar_from_u64(u64::from(sh.0));
            let pv = eval_poly(&values, &point);
            let rv = eval_poly(&rands, &point);

            let p0 = commitment_to_share(sh, &coeffs);
            assert_eq!(
                p0,
                ck.hide(
                    PedersenValue::view_scalar(&pv),
                    Randomness::view_scalar(&rv)
                )
            );
        }
    }

    /// Check IP's verify_credentials succeeds for well-formed data.
    #[test]
    fn test_verify_credentials_success() {
        // Arrange (create identity provider and PreIdentityObject, and verify validity)
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (
            IpData {
                public_ip_info: ip_info,
                ip_secret_key,
                metadata: _,
            },
            _,
        ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let aci = test_create_aci(&mut csprng);
        let (_, pio, _) = test_create_pio(&aci, &ip_info, num_ars);
        let attrs = test_create_attributes();

        // Act
        let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);

        // Assert
        assert!(sig_ok.is_ok());
    }

    // /// Check IP's verify_credentials fail for wrong id_cred_sec
    // proof-of-knowledge.
    // #[test]
    // fn test_verify_credentials_fail_pok_idcredsec() {
    // Arrange
    // let max_attrs = 10;
    // let num_ars = 4;
    // let mut csprng = thread_rng();
    // let (
    // IpData {
    // public_ip_info: ip_info,
    // ip_secret_key,
    // metadata: _,
    // },
    // _,
    // ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
    // let aci = test_create_aci(&mut csprng);
    // let (_, mut pio, _) = test_create_pio(&aci, &ip_info, num_ars);
    // let attrs = test_create_attributes();
    //
    // Act (make dlog proof use wrong id_cred_sec)
    // let wrong_id_cred_sec = ExampleCurve::generate_scalar(&mut csprng);
    // pio.pok_sc = prove_dlog(
    // &mut csprng,
    // RandomOracle::empty(),
    // &pio.id_cred_pub,
    // &wrong_id_cred_sec,
    // &ip_info.ip_ars.ar_base,
    // );
    // let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);
    //
    // Assert
    // if sig_ok.is_ok() {
    // assert_eq!(
    // wrong_id_cred_sec,
    // aci.cred_holder_info.id_cred.id_cred_sec.value
    // );
    // }
    // assert_eq!(
    // sig_ok,
    // Err(Reason::FailedToVerifyKnowledgeOfIdCredSec),
    // "Verify_credentials did not fail on invalid IdCredSec PoK"
    // )
    // }

    /// Test IP's verify_credentials fail if discrete log of idcredpub and
    /// elgamal encryption are different
    #[test]
    fn test_verify_credentials_fail_idcredsec_equality() {
        // Arrange
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (
            IpData {
                public_ip_info: ip_info,
                ip_secret_key,
                metadata: _,
            },
            _,
        ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let aci = test_create_aci(&mut csprng);
        let (ctx, mut pio, _) = test_create_pio(&aci, &ip_info, num_ars);
        let attrs = test_create_attributes();

        // Act (make cmm_sc be comm. of id_cred_sec but with wrong/fresh randomness)
        let sc_ck = CommitmentKey(ctx.ip_info.ip_verify_key.ys[0], ctx.ip_info.ip_verify_key.g);
        let id_cred_sec = aci.cred_holder_info.id_cred.id_cred_sec.value;
        let val = curve_arithmetic::secret_value::Value::from_scalar(id_cred_sec);
        let (cmm_sc, _) = sc_ck.commit(&val, &mut csprng);
        pio.cmm_sc = cmm_sc;
        let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);

        // Assert
        assert_eq!(
            sig_ok,
            Err(Reason::IncorrectProof),
            "Verify_credentials did not fail with inconsistent idcredpub and elgamal"
        );
    }

    /// Test IP's verify_credentials fails if the PRF key check fail.
    #[test]
    fn test_verify_credentials_fail_prf_data() {
        // Arrange
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (
            IpData {
                public_ip_info: ip_info,
                ip_secret_key,
                metadata: _,
            },
            _,
        ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
        let aci = test_create_aci(&mut csprng);
        let (_, mut pio, _) = test_create_pio(&aci, &ip_info, num_ars);
        let attrs = test_create_attributes();

        // Act (make cmm_prf be a commitment to a wrong/random value)
        let ck = ip_info.ip_ars.ar_cmm_key;
        let val = curve_arithmetic::secret_value::Value::generate(&mut csprng);
        let (cmm_prf, _) = ck.commit(&val, &mut csprng);
        pio.cmm_prf = cmm_prf;
        let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);

        // Assert
        assert_eq!(
            sig_ok,
            Err(Reason::IncorrectProof),
            "Verify_credentials did not fail with invalid PRF commitment"
        );
    }
}
