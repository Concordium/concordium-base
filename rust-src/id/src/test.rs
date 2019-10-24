use crate::{
    account_holder::*, anonymity_revoker::*, chain::*, ffi::*, identity_provider::*, types::*,
};
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519 as ed25519;
use elgamal::{public::PublicKey, secret::SecretKey};
use pairing::bls12_381::{Bls12, G1};
use ps_sig;
use secret_sharing::secret_sharing::Threshold;

use rand::*;

use pedersen_scheme::key as pedersen_key;

use std::io::Cursor;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

#[test]
fn test_pipeline() {
    let mut csprng = thread_rng();

    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let public = ExampleCurve::one_point().mul_by_scalar(&secret);
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_ah:   "ACCOUNT_HOLDER".to_owned(),
        id_cred: IdCredentials {
            id_cred_sec: secret,
            id_cred_pub: public,
        },
    };

    let ip_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(10, &mut csprng);
    let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);

    let ar1_secret_key = SecretKey::generate(&mut csprng);
    let ar1_public_key = PublicKey::from(&ar1_secret_key);
    let ar1_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(1),
        ar_description: "A good AR".to_string(),
        ar_public_key:  ar1_public_key,
    };

    let ar2_secret_key = SecretKey::generate(&mut csprng);
    let ar2_public_key = PublicKey::from(&ar2_secret_key);
    let ar2_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(2),
        ar_description: "A nice AR".to_string(),
        ar_public_key:  ar2_public_key,
    };

    let ar3_secret_key = SecretKey::generate(&mut csprng);
    let ar3_public_key = PublicKey::from(&ar3_secret_key);
    let ar3_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(3),
        ar_description: "Weird AR".to_string(),
        ar_public_key:  ar3_public_key,
    };

    let ar4_secret_key = SecretKey::generate(&mut csprng);
    let ar4_public_key = PublicKey::from(&ar4_secret_key);
    let ar4_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(4),
        ar_description: "Ok AR".to_string(),
        ar_public_key:  ar4_public_key,
    };

    let ar_ck = pedersen_key::CommitmentKey::generate(&mut csprng);
    let dlog_base = <G1 as Curve>::one_point();
    // let dlog_base = <G1 as Curve>::generate(&mut csprng);

    let ip_info = IpInfo {
        ip_identity: IpIdentity(88),
        ip_description: "IP88".to_string(),
        ip_verify_key: ip_public_key,
        dlog_base,
        ar_info: (vec![ar1_info, ar2_info, ar3_info, ar4_info], ar_ck),
    };

    let prf_key = prf::SecretKey::generate(&mut csprng);

    let variant = 0;
    let expiry_date = 123123123;
    let alist = vec![AttributeKind::from(55), AttributeKind::from(31)];
    let aci = AccCredentialInfo {
        acc_holder_info: ah_info,
        prf_key,
        attributes: ExampleAttributeList {
            variant,
            expiry: expiry_date,
            alist,
            _phantom: Default::default(),
        },
    };

    let context = make_context_from_ip_info(
        ip_info.clone(),
        (
            vec![ArIdentity(1), ArIdentity(2), ArIdentity(4)],
            Threshold(2),
        ),
    );
    let (pio, randomness) = generate_pio(&context, &aci);

    let sig_ok = verify_credentials(&pio, &ip_info, &ip_secret_key);

    // First test, check that we have a valid signature.
    assert!(sig_ok.is_ok());

    let ip_sig = sig_ok.unwrap();

    let global_ctx = GlobalContext {
        dlog_base_chain:         ExampleCurve::one_point(),
        on_chain_commitment_key: pedersen_key::CommitmentKey::generate(&mut csprng),
    };

    let policy = Policy {
        variant,
        expiry: expiry_date,
        policy_vec: vec![(1, AttributeKind::from(31))],
        _phantom: Default::default(),
    };

    let kp = ed25519::generate_keypair();
    let acc_data = AccountData {
        sign_key:   kp.secret,
        verify_key: kp.public,
    };

    let cdi = generate_cdi(
        &ip_info,
        &global_ctx,
        &aci,
        &pio,
        0,
        &ip_sig,
        &policy,
        &acc_data,
        &randomness,
    );

    // let mut out = Vec::new();
    // let gc_bytes = global_ctx.to_bytes();
    // out.extend_from_slice(&(gc_bytes.len() as u32).to_be_bytes());
    // out.extend_from_slice(&gc_bytes);
    // let ip_info_bytes = ip_info.to_bytes();
    // out.extend_from_slice(&(ip_info_bytes.len() as u32).to_be_bytes());
    // out.extend_from_slice(&ip_info_bytes);
    // out.extend_from_slice(&cdi.to_bytes());
    // let file = File::create("foo.bin");
    // file.unwrap().write_all(&out);

    let value_bytes = cdi.values.to_bytes();
    let cdi_values = CredentialDeploymentValues::<ExampleCurve, ExampleAttribute>::from_bytes(
        &mut Cursor::new(&value_bytes),
    );
    assert!(
        cdi_values.is_some(),
        "VALUES Deserialization must be successful."
    );

    let cmm_bytes = cdi.proofs.commitments.to_bytes();
    let cdi_commitments =
        CredDeploymentCommitments::<ExampleCurve>::from_bytes(&mut Cursor::new(&cmm_bytes));
    assert!(
        cdi_commitments.is_some(),
        "commitments Deserialization must be successful."
    );

    let proofs_bytes = cdi.proofs.to_bytes();
    let cdi_proofs =
        CredDeploymentProofs::<Bls12, ExampleCurve>::from_bytes(&mut Cursor::new(&proofs_bytes));
    assert!(
        cdi_proofs.is_some(),
        "Proofs Deserialization must be successful."
    );

    let bytes = cdi.to_bytes();
    let des = CredDeploymentInfo::<Bls12, ExampleCurve, ExampleAttribute>::from_bytes(
        &mut Cursor::new(&bytes),
    );
    assert!(des.is_some(), "Deserialization must be successful.");
    // FIXME: Have better equality instances for CDI that do not place needless
    // restrictions on the pairing (such as having PartialEq instnace).
    // For now we just check that the last item in the proofs deserialized
    // correctly.
    assert_eq!(
        des.unwrap().proofs.proof_policy,
        cdi.proofs.proof_policy,
        "It should deserialize back to what we started with."
    );

    // assert_eq!(4, cdi.commitments.cmm_attributes.len(), "Attribute list length
    // check."); now check that the generated credentials are indeed valid.
    let cdi_check = verify_cdi(&global_ctx, &ip_info, &cdi);
    assert_eq!(cdi_check, Ok(()));

    // revoking anonymity
    let second_ar = cdi
        .values
        .ar_data
        .iter()
        .find(|&x| x.ar_identity == ArIdentity(2))
        .unwrap();
    let decrypted_share_ar2 = (
        second_ar.id_cred_pub_share_number.into(),
        ar2_secret_key.decrypt(&second_ar.enc_id_cred_pub_share),
    );
    let fourth_ar = cdi
        .values
        .ar_data
        .iter()
        .find(|&x| x.ar_identity == ArIdentity(4))
        .unwrap();
    let decrypted_share_ar4 = (
        fourth_ar.id_cred_pub_share_number,
        ar4_secret_key.decrypt(&fourth_ar.enc_id_cred_pub_share),
    );
    let revealed_id_cred_pub = reveal_id_cred_pub(&vec![decrypted_share_ar2, decrypted_share_ar4]);
    assert_eq!(
        revealed_id_cred_pub,
        aci.acc_holder_info.id_cred.id_cred_pub
    );

    // generate a new cdi from a modified pre-identity object in which we swapped
    // two anonymity revokers. Verification of this credential should fail the
    // signature at the very least.
    let mut cdi = generate_cdi(
        &ip_info,
        &global_ctx,
        &aci,
        &pio,
        0,
        &ip_sig,
        &policy,
        &acc_data,
        &randomness,
    );
    cdi.values.ar_data.rotate_left(1);
    let cdi_check = verify_cdi(&global_ctx, &ip_info, &cdi);
    assert_ne!(cdi_check, Ok(()));
}
