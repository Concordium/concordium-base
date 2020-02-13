use crate::{
    account_holder::*, anonymity_revoker::*, chain::*, ffi::*, identity_provider::*,
    secret_sharing::Threshold, types::*,
};
use crypto_common::*;
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use elgamal::{public::PublicKey, secret::SecretKey};
use pairing::bls12_381::{Bls12, G1};
use ps_sig;
use std::collections::btree_map::BTreeMap;

use rand::*;

use pedersen_scheme::{key as pedersen_key, Value as PedersenValue};

use either::Left;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

// use std::{io::Write,fs::File};

#[test]
fn test_pipeline() {
    let mut csprng = thread_rng();

    let ip_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(10, &mut csprng);
    let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);

    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_ah:   "ACCOUNT_HOLDER".to_owned(),
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue::new(secret),
        },
    };

    let ar_base = ExampleCurve::generate(&mut csprng);

    let ar1_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar1_public_key = PublicKey::from(&ar1_secret_key);
    let ar1_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(1),
        ar_description: "A good AR".to_string(),
        ar_public_key:  ar1_public_key,
    };

    let ar2_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar2_public_key = PublicKey::from(&ar2_secret_key);
    let ar2_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(2),
        ar_description: "A nice AR".to_string(),
        ar_public_key:  ar2_public_key,
    };

    let ar3_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar3_public_key = PublicKey::from(&ar3_secret_key);
    let ar3_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(3),
        ar_description: "Weird AR".to_string(),
        ar_public_key:  ar3_public_key,
    };

    let ar4_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar4_public_key = PublicKey::from(&ar4_secret_key);
    let ar4_info = ArInfo::<G1> {
        ar_identity:    ArIdentity(4),
        ar_description: "Ok AR".to_string(),
        ar_public_key:  ar4_public_key,
    };

    let ar_ck = pedersen_key::CommitmentKey::generate(&mut csprng);

    let ip_info = IpInfo {
        ip_identity:    IpIdentity(88),
        ip_description: "IP88".to_string(),
        ip_verify_key:  ip_public_key,
        ip_ars:         IpAnonymityRevokers {
            ars: vec![ar1_info, ar2_info, ar3_info, ar4_info],
            ar_cmm_key: ar_ck,
            ar_base,
        },
    };

    let prf_key = prf::SecretKey::generate(&mut csprng);

    let expiry_date = 123123123;
    let alist = {
        let mut alist = BTreeMap::new();
        alist.insert(AttributeTag::from(0u8), AttributeKind::from(55));
        alist.insert(AttributeTag::from(8u8), AttributeKind::from(31));
        alist
    };
    let aci = AccCredentialInfo {
        cred_holder_info: ah_info,
        prf_key,
    };

    let alist = ExampleAttributeList {
        expiry: expiry_date,
        alist,
        _phantom: Default::default(),
    };

    let context = make_context_from_ip_info(ip_info.clone(), ChoiceArParameters {
        ar_identities: vec![ArIdentity(1), ArIdentity(2), ArIdentity(4)],
        threshold:     Threshold(2),
    })
    .expect("The constructed ARs are valid.");
    let (pio, randomness) = generate_pio(&context, &aci);

    let sig_ok = verify_credentials(&pio, &ip_info, &alist, &ip_secret_key);

    // First test, check that we have a valid signature.
    assert!(sig_ok.is_ok());

    let ip_sig = sig_ok.unwrap();

    let global_ctx = GlobalContext {
        on_chain_commitment_key: pedersen_key::CommitmentKey::generate(&mut csprng),
    };

    let policy = Policy {
        expiry:     expiry_date,
        policy_vec: {
            let mut tree = BTreeMap::new();
            tree.insert(AttributeTag::from(8u8), AttributeKind::from(31));
            tree
        },
        _phantom:   Default::default(),
    };

    let mut keys = BTreeMap::new();
    keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
    keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
    keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

    let acc_data = AccountData {
        keys,
        existing: Left(SignatureThreshold(2)),
    };

    let id_use_data = IdObjectUseData { aci, randomness };

    let id_object = IdentityObject {
        pre_identity_object: pio,
        alist,
        signature: ip_sig,
    };

    let cdi = generate_cdi(
        &ip_info,
        &global_ctx,
        &id_object,
        &id_use_data,
        0,
        &policy,
        &acc_data,
    )
    .expect("Should generate the credential successfully.");

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

    let cdi_values = serialize_deserialize(&cdi.values);
    assert!(
        cdi_values.is_ok(),
        "VALUES Deserialization must be successful."
    );

    let cdi_commitments = serialize_deserialize(&cdi.proofs.commitments);
    assert!(
        cdi_commitments.is_ok(),
        "commitments Deserialization must be successful."
    );

    let cdi_proofs = serialize_deserialize(&cdi.proofs);
    assert!(
        cdi_proofs.is_ok(),
        "Proof deserialization must be successful."
    );

    let des = serialize_deserialize(&cdi);
    assert!(des.is_ok(), "Deserialization must be successful.");
    // FIXME: Have better equality instances for CDI that do not place needless
    // restrictions on the pairing (such as having PartialEq instnace).
    // For now we just check that the last item in the proofs deserialized
    // correctly.
    assert_eq!(
        des.unwrap().proofs.proof_reg_id,
        cdi.proofs.proof_reg_id,
        "It should deserialize back to what we started with."
    );

    // assert_eq!(4, cdi.commitments.cmm_attributes.len(), "Attribute list length
    // check."); now check that the generated credentials are indeed valid.
    let cdi_check = verify_cdi(&global_ctx, &ip_info, None, &cdi);
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
        ip_info
            .ip_ars
            .ar_base
            .mul_by_scalar(&id_use_data.aci.cred_holder_info.id_cred.id_cred_sec)
    );

    // generate a new cdi from a modified pre-identity object in which we swapped
    // two anonymity revokers. Verification of this credential should fail the
    // signature at the very least.
    let mut cdi = generate_cdi(
        &ip_info,
        &global_ctx,
        &id_object,
        &id_use_data,
        0,
        &policy,
        &acc_data,
    )
    .expect("Should generate the credential successfully.");
    cdi.values.ar_data.rotate_left(1);
    let cdi_check = verify_cdi(&global_ctx, &ip_info, None, &cdi);
    assert_ne!(cdi_check, Ok(()));
}
