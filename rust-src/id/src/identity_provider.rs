use crate::{
    secret_sharing::{ShareNumber, Threshold},
    sigma_protocols::{com_enc_eq::*, com_eq::*, com_eq_different_groups::*, dlog::*},
    types::*,
};
use curve_arithmetic::{Curve, Pairing};

use random_oracle::RandomOracle;

use ff::Field;
use pedersen_scheme::{commitment::Commitment, key::CommitmentKey};
use ps_sig;
use rand::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    FailedToVerifyKnowledgeOfIdCredSec,
    FailedToVerifyIdCredSecEquality,
    FailedToVerifyPrfData,
    WrongArParameters,
    IllegalAttributeRequirements,
}

fn check_ar_parameters<C: Curve>(
    _choice_ar_parameters: &(Vec<ArInfo<C>>, Threshold),
    _ip_ar_info: &[ArInfo<C>],
) -> bool {
    // some business logic here
    true
}
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
    let commitment_key_sc = CommitmentKey(ip_info.ip_verify_key.ys[0], ip_info.ip_verify_key.g);
    let commitment_key_prf = CommitmentKey(ip_info.ip_verify_key.ys[1], ip_info.ip_verify_key.g);

    let b_1 = verify_dlog(
        RandomOracle::empty(),
        &ip_info.ip_ars.ar_base,
        &pre_id_obj.id_cred_pub,
        &pre_id_obj.pok_sc,
    );
    if !b_1 {
        return Err(Reason::FailedToVerifyKnowledgeOfIdCredSec);
    }

    let b_11 = verify_com_eq_single::<P::G1, C>(
        RandomOracle::empty(),
        &pre_id_obj.cmm_sc,
        &pre_id_obj.id_cred_pub,
        &commitment_key_sc,
        &ip_info.ip_ars.ar_base,
        &pre_id_obj.proof_com_eq_sc,
    );

    if !b_11 {
        return Err(Reason::FailedToVerifyIdCredSecEquality);
    }

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
    let b_2 = verify_prf_key_data(
        &commitment_key_prf,
        &pre_id_obj.cmm_prf,
        &ar_ck,
        &pre_id_obj.cmm_prf_sharing_coeff,
        &pre_id_obj.ip_ar_data,
        &choice_ar_parameters.0,
        &pre_id_obj.proof_com_eq,
    );

    if !b_2 {
        return Err(Reason::FailedToVerifyPrfData);
    }
    let message: ps_sig::UnknownMessage<P> = compute_message(
        &pre_id_obj.cmm_prf,
        &pre_id_obj.cmm_sc,
        pre_id_obj.choice_ar_parameters.threshold,
        &choice_ar_handles,
        &alist,
        &ip_info.ip_verify_key,
    )?;
    let mut csprng = thread_rng();
    Ok(ip_secret_key.sign_unknown_message(&message, &mut csprng))
}

fn compute_message<P: Pairing, AttributeType: Attribute<P::ScalarField>>(
    cmm_prf: &Commitment<P::G1>,
    cmm_sc: &Commitment<P::G1>,
    threshold: Threshold,
    ar_list: &[ArIdentity],
    att_list: &AttributeList<P::ScalarField, AttributeType>,
    ps_public_key: &ps_sig::PublicKey<P>,
) -> Result<ps_sig::UnknownMessage<P>, Reason> {
    // TODO: handle the errors
    let expiry = P::G1::scalar_from_u64(att_list.expiry.into());
    let creation_time = P::G1::scalar_from_u64(att_list.creation_time.into());

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
    // - expiry date of the attribute list
    // - creation time of the attribute list
    // - attribute list elements

    let mut message = cmm_sc.0;
    message = message.plus_point(&cmm_prf.0);
    let att_vec = &att_list.alist;
    let m = ar_list.len();
    let n = att_vec.len();
    let key_vec = &ps_public_key.ys;

    // FIXME: Handle error gracefully, do not panic.
    assert!(key_vec.len() >= n + m + 3 + 3);

    // add threshold to the message
    message = message.plus_point(&key_vec[2].mul_by_scalar(&threshold.to_scalar::<P::G1>()));
    // and add all anonymity revocation
    for i in 3..(m + 3) {
        let ar_handle = ar_list[i - 3].to_scalar::<P::G1>();
        message = message.plus_point(&key_vec[i].mul_by_scalar(&ar_handle));
    }

    message = message.plus_point(&key_vec[m + 3].mul_by_scalar(&tags));
    message = message.plus_point(&key_vec[m + 3 + 1].mul_by_scalar(&expiry));
    message = message.plus_point(&key_vec[m + 3 + 2].mul_by_scalar(&creation_time));
    // NB: It is crucial that att_vec is an ordered map and that .values iterator
    // returns messages in order of tags.
    for (k, v) in key_vec.iter().skip(m + 3 + 3).zip(att_vec.values()) {
        let att = v.to_field_element();
        message = message.plus_point(&k.mul_by_scalar(&att));
    }
    let msg = ps_sig::UnknownMessage(message);
    Ok(msg)
}

fn verify_prf_key_data<C1: Curve, C2: Curve<Scalar = C1::Scalar>>(
    ip_commitment_key: &CommitmentKey<C1>,
    cmm_vrf: &Commitment<C1>,
    ar_commitment_key: &CommitmentKey<C2>,
    cmm_sharing_coeff: &[Commitment<C2>],
    ip_ar_data: &[IpArData<C2>],
    choice_ar_parameters: &[ArInfo<C2>],
    com_eq_diff_grps_proof: &ComEqDiffGrpsProof<C1, C2>,
) -> bool {
    // FIXME: Figure out the prefix that should be used (to make the proof
    // non-copyable)
    let b_1 = verify_com_eq_diff_grps::<C1, C2>(
        RandomOracle::empty(),
        cmm_vrf,
        &cmm_sharing_coeff[0],
        ip_commitment_key,
        ar_commitment_key,
        com_eq_diff_grps_proof,
    );
    if !b_1 {
        return false;
    }

    for ar in ip_ar_data.iter() {
        let cmm_share = commitment_to_share(ar.prf_key_share_number, cmm_sharing_coeff);
        // finding the right encryption key
        match choice_ar_parameters
            .iter()
            .find(|&x| x.ar_identity == ar.ar_identity)
        {
            None => return false,
            Some(ar_info) => {
                // FIXME: Figure out the prefix that should be used.
                if !verify_com_enc_eq(
                    RandomOracle::empty(),
                    &ar.enc_prf_key_share,
                    &cmm_share,
                    &ar_info.ar_public_key,
                    ar_commitment_key,
                    &ar.proof_com_enc_eq,
                ) {
                    return false;
                }
            }
        }
    }
    true
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

    use crate::{account_holder::generate_pio, ffi::*};

    use dodis_yampolskiy_prf::secret as prf;
    use elgamal::{public::PublicKey, secret::SecretKey};
    use ff::PrimeField;
    use pairing::bls12_381::{Bls12, G1};
    use pedersen_scheme::{
        key as PedersenKey, key::CommitmentKey, Randomness, Value as PedersenValue,
    };
    use rand::seq::SliceRandom;
    use std::{collections::btree_map::BTreeMap, convert::TryFrom};

    type ExamplePairing = Bls12;
    type ExampleCurve = G1;
    type ExampleAttribute = AttributeKind;
    type ExampleAttributeList =
        AttributeList<<ExamplePairing as Pairing>::ScalarField, ExampleAttribute>;

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

    /// Create identity provider with #num_ars anonymity revokers to be used by
    /// tests
    fn create_test_ip_info<T: Rng>(
        csprng: &mut T,
        num_ars: u32,
        max_attrs: u32,
    ) -> (
        IpInfo<ExamplePairing, ExampleCurve>,
        ps_sig::secret::SecretKey<ExamplePairing>,
    ) {
        // Create key for IP long enough to encode the attributes and anonymity
        // revokers.
        let ps_len = (5 + num_ars + max_attrs) as usize;
        let ip_secret_key = ps_sig::secret::SecretKey::<ExamplePairing>::generate(ps_len, csprng);
        let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);

        // Create ARs
        let ar_ck = PedersenKey::CommitmentKey::generate(csprng);
        let ar_base = ExampleCurve::generate(csprng);
        let mut ar_infos = Vec::new();
        for i in 0..num_ars {
            let ar_secret_key = SecretKey::generate(&ar_base, csprng);
            let ar_public_key = PublicKey::from(&ar_secret_key);
            let ar_info = ArInfo::<ExampleCurve> {
                ar_identity: ArIdentity(i),
                ar_description: mk_dummy_description(format!("AnonymityRevoker{}", i)),
                ar_public_key,
            };
            ar_infos.push(ar_info);
        }

        // Return IP-info and secret-key
        (
            IpInfo {
                ip_identity:    IpIdentity(0),
                ip_description: mk_dummy_description("IP0".to_string()),
                ip_verify_key:  ip_public_key,
                ip_ars:         IpAnonymityRevokers {
                    ars: ar_infos,
                    ar_cmm_key: ar_ck,
                    ar_base,
                },
            },
            ip_secret_key,
        )
    }

    /// Create PreIdentityObject for an account holder to be used by tests,
    /// with the anonymity revocation having random threshold between 1 and
    /// num_ars
    fn create_test_pio<T: Rng>(
        csprng: &mut T,
        ip_info: &IpInfo<ExamplePairing, ExampleCurve>,
        num_ars: u32,
    ) -> (
        Context<ExamplePairing, ExampleCurve>,
        PreIdentityObject<ExamplePairing, ExampleCurve>,
        <G1 as Curve>::Scalar,
    ) {
        // Create account holder
        let secret = ExampleCurve::generate_scalar(csprng);
        let ah_info = CredentialHolderInfo::<ExampleCurve> {
            id_cred: IdCredentials {
                id_cred_sec: PedersenValue::new(secret),
            },
        };

        // Create credential information
        let prf_key = prf::SecretKey::generate(csprng);
        let aci = AccCredentialInfo {
            cred_holder_info: ah_info,
            prf_key,
        };

        // Select some ARs, between one and all
        let threshold = csprng.gen_range(1, num_ars + 1);

        // select threshold number of anonymity revokers, in some order.
        let ar_ids: Vec<ArIdentity> = (0..num_ars).map(ArIdentity).collect::<Vec<_>>();
        let ars = ar_ids
            .choose_multiple(csprng, threshold as usize)
            .cloned()
            .collect();

        // Create context
        let context = make_context_from_ip_info(ip_info.clone(), ChoiceArParameters {
            ar_identities: ars,
            threshold:     Threshold(threshold),
        })
        .expect("The constructed ARs are invalid.");

        // Create and return PIO
        let (pio, _randomness) = generate_pio::<ExamplePairing, ExampleCurve>(&context, &aci);
        (context, pio, secret)
    }

    /// Create example attributes to be used by tests.
    /// The attributes are generated uniformly at random, and the number of
    /// attributes is chosen uniformly at random in the range [0, max_attrs)
    fn create_test_attributes<R: Rng>(rng: &mut R, max_attrs: u32) -> ExampleAttributeList {
        let mut alist = BTreeMap::new();

        let numattrs = rng.gen_range(0, max_attrs);
        // capacity is the number of bits we can reliably store in a field
        // element of a pairing.
        let capacity = <ExamplePairing as Pairing>::ScalarField::CAPACITY;
        for _i in 0..numattrs {
            // tags must be < capacity in order for the current encoding to work.
            let tag = (rng.next_u32() % capacity) as u8;
            let kind = rng.next_u64();
            alist.insert(AttributeTag::from(tag), AttributeKind::from(kind));
        }

        let expiry_year = 2000 + (rng.next_u64() % 100);
        let expiry_month = 1 + (rng.next_u64() % 12);
        let expiry = YearMonth::try_from(expiry_year << 8 | expiry_month).unwrap();

        let creation_year = expiry_year - 2;
        let creation_time = YearMonth::try_from(creation_year << 8 | expiry_month).unwrap();
        ExampleAttributeList {
            expiry,
            creation_time,
            alist,
            _phantom: Default::default(),
        }
    }

    /// Check IP's verify_credentials succeeds for well-formed data.
    #[test]
    fn test_verify_credentials_success() {
        // Arrange (create identity provider and PreIdentityObject, and verify validity)
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (ip_info, ip_secret_key) = create_test_ip_info(&mut csprng, num_ars, max_attrs);
        let (_, pio, _) = create_test_pio(&mut csprng, &ip_info, num_ars);
        let attrs = create_test_attributes(&mut csprng, max_attrs);

        // Act
        let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);

        // Assert
        assert!(sig_ok.is_ok());
    }

    /// Check IP's verify_credentials fail for wrong id_cred_sec
    /// proof-of-knowledge.
    #[test]
    fn test_verify_credentials_fail_pok_idcredsec() {
        // Arrange
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (ip_info, ip_secret_key) = create_test_ip_info(&mut csprng, num_ars, max_attrs);
        let (_, mut pio, id_cred_sec) = create_test_pio(&mut csprng, &ip_info, num_ars);
        let attrs = create_test_attributes(&mut csprng, max_attrs);

        // Act (make dlog proof use wrong id_cred_sec)
        let wrong_id_cred_sec = ExampleCurve::generate_scalar(&mut csprng);
        pio.pok_sc = prove_dlog(
            &mut csprng,
            RandomOracle::empty(),
            &pio.id_cred_pub,
            &wrong_id_cred_sec,
            &ip_info.ip_ars.ar_base,
        );
        let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);

        // Assert
        if sig_ok.is_ok() {
            assert_eq!(wrong_id_cred_sec, id_cred_sec);
        }
        assert_eq!(
            sig_ok,
            Err(Reason::FailedToVerifyKnowledgeOfIdCredSec),
            "Verify_credentials did not fail on invalid IdCredSec PoK"
        )
    }

    /// Test IP's verify_credentials fail if discrete log of idcredpub and
    /// elgamal encryption are different
    #[test]
    fn test_verify_credentials_fail_idcredsec_equality() {
        // Arrange
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (ip_info, ip_secret_key) = create_test_ip_info(&mut csprng, num_ars, max_attrs);
        let (ctx, mut pio, id_cred_sec) = create_test_pio(&mut csprng, &ip_info, num_ars);
        let attrs = create_test_attributes(&mut csprng, max_attrs);

        // Act (make cmm_sc be comm. of id_cred_sec but with wrong/fresh randomness)
        let sc_ck = CommitmentKey(ctx.ip_info.ip_verify_key.ys[0], ctx.ip_info.ip_verify_key.g);
        let val = curve_arithmetic::secret_value::Value::from_scalar(id_cred_sec);
        let (cmm_sc, _) = sc_ck.commit(&val, &mut csprng);
        pio.cmm_sc = cmm_sc;
        let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);

        // Assert
        assert_eq!(
            sig_ok,
            Err(Reason::FailedToVerifyIdCredSecEquality),
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
        let (ip_info, ip_secret_key) = create_test_ip_info(&mut csprng, num_ars, max_attrs);
        let (_, mut pio, _) = create_test_pio(&mut csprng, &ip_info, num_ars);
        let attrs = create_test_attributes(&mut csprng, max_attrs);

        // Act (make cmm_prf be a commitment to a wrong/random value)
        let ck = ip_info.ip_ars.ar_cmm_key;
        let val = curve_arithmetic::secret_value::Value::generate(&mut csprng);
        let (cmm_prf, _) = ck.commit(&val, &mut csprng);
        pio.cmm_prf = cmm_prf;
        let sig_ok = verify_credentials(&pio, &ip_info, &attrs, &ip_secret_key);

        // Assert
        assert_eq!(
            sig_ok,
            Err(Reason::FailedToVerifyPrfData),
            "Verify_credentials did not fail with invalid PRF commitment"
        );
    }
}
