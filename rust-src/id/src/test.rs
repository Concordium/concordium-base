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
use pedersen_scheme::{key as pedersen_key, Value as PedersenValue};
use ps_sig;
use rand::*;
use std::{collections::btree_map::BTreeMap, convert::TryFrom};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;
#[cfg(all(target_arch = "wasm32", feature = "wasm-browser-test"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

use either::Left;

type ExamplePairing = Bls12;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

/// Create #num_ars anonymity revokers to be used by test
pub fn test_create_ars<T: Rng>(
    ar_base: &ExampleCurve,
    num_ars: u8,
    csprng: &mut T,
) -> (Vec<ArInfo<ExampleCurve>>, Vec<SecretKey<ExampleCurve>>) {
    let mut ar_infos = Vec::new();
    let mut ar_keys = Vec::new();
    for i in 0..num_ars {
        let ar_secret_key = SecretKey::generate(ar_base, csprng);
        let ar_public_key = PublicKey::from(&ar_secret_key);
        let ar_info = ArInfo::<ExampleCurve> {
            ar_identity: ArIdentity(i as u32),
            ar_description: Description {
                name: format!("AnonymityRevoker{}", i),
                url: format!("AnonymityRevoker{}.com", i),
                description: format!("AnonymityRevoker{}", i),
            },
            ar_public_key,
        };
        ar_infos.push(ar_info);
        ar_keys.push(ar_secret_key);
    }
    (ar_infos, ar_keys)
}

/// Create identity provider with #num_ars ARs to be used by tests
pub fn test_create_ip_info<T: Rng>(
    csprng: &mut T,
    num_ars: u8,
    max_attrs: u8,
) -> (
    IpData<ExamplePairing, ExampleCurve>,
    Vec<SecretKey<ExampleCurve>>,
) {
    // Create key for IP long enough to encode the attributes and anonymity
    // revokers.
    let ps_len = (5 + num_ars + max_attrs) as usize;
    let ip_secret_key = ps_sig::secret::SecretKey::<ExamplePairing>::generate(ps_len, csprng);
    let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);

    // Create ARs
    let ar_ck = pedersen_key::CommitmentKey::generate(csprng);
    let ar_base = ExampleCurve::generate(csprng);
    let (ar_infos, ar_keys) = test_create_ars(&ar_base, num_ars, csprng);

    // Return IpData with public info and private key
    (
        IpData {
            public_ip_info: IpInfo {
                ip_identity: IpIdentity(0),
                ip_description: Description {
                    name: "IP0".to_owned(),
                    url: "IP0.com".to_owned(),
                    description: "IP0".to_owned(),
                },
                ip_verify_key: ip_public_key,
                ip_ars: IpAnonymityRevokers {
                    ars: ar_infos,
                    ar_cmm_key: ar_ck,
                    ar_base,
                },
            },
            ip_secret_key,
            metadata: IpMetadata {
                issuance_start: "URL.com".to_owned(),
                icon: "BeautifulIcon.ico".to_owned(),
            },
        },
        ar_keys,
    )
}

/// Create random AccCredentialInfo (ACI) to be used by tests
pub fn test_create_aci<T: Rng>(csprng: &mut T) -> AccCredentialInfo<ExampleCurve> {
    let secret = ExampleCurve::generate_scalar(csprng);
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue::new(secret),
        },
    };

    let prf_key = prf::SecretKey::generate(csprng);
    AccCredentialInfo {
        cred_holder_info: ah_info,
        prf_key,
    }
}

/// Create PreIdentityObject for an account holder to be used by tests,
/// with the anonymity revocation using all but the last AR.
pub fn test_create_pio(
    aci: &AccCredentialInfo<ExampleCurve>,
    ip_info: &IpInfo<ExamplePairing, ExampleCurve>,
    num_ars: u8,
) -> (
    Context<ExamplePairing, ExampleCurve>,
    PreIdentityObject<ExamplePairing, ExampleCurve>,
    ps_sig::SigRetrievalRandomness<ExamplePairing>,
) {
    // Select all ARs except last one
    let threshold = num_ars as u32 - 1;
    let ars: Vec<ArIdentity> = (0..threshold).map(ArIdentity).collect::<Vec<_>>();

    // Create context
    let context = make_context_from_ip_info(
        ip_info.clone(),
        ChoiceArParameters {
            ar_identities: ars,
            threshold: Threshold(threshold),
        },
    )
    .expect("The constructed ARs are invalid.");

    // Create and return PIO
    let (pio, randomness) = generate_pio(&context, &aci);
    (context, pio, randomness)
}

/// Create example attributes to be used by tests.
/// The attributes are hardcoded, one (8u8) being in the policy
pub fn test_create_attributes() -> ExampleAttributeList {
    let mut alist = BTreeMap::new();
    alist.insert(AttributeTag::from(0u8), AttributeKind::from(55));
    alist.insert(AttributeTag::from(8u8), AttributeKind::from(31));

    let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
    let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
    ExampleAttributeList {
        valid_to,
        created_at,
        alist,
        _phantom: Default::default(),
    }
}

pub fn test_pipeline() {
    let mut csprng = thread_rng();

    // Generate PIO
    let max_attrs = 10;
    let num_ars = 5;
    let (
        IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            metadata: _,
        },
        ar_keys,
    ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);
    let aci = test_create_aci(&mut csprng);
    let (_context, pio, randomness) = test_create_pio(&aci, &ip_info, num_ars);
    let alist = test_create_attributes();
    let sig_ok = verify_credentials(&pio, &ip_info, &alist, &ip_secret_key);
    assert!(sig_ok.is_ok());

    // Generate CDI
    let ip_sig = sig_ok.unwrap();
    let global_ctx = GlobalContext {
        on_chain_commitment_key: pedersen_key::CommitmentKey::generate(&mut csprng),
    };
    let id_object = IdentityObject {
        pre_identity_object: pio,
        alist,
        signature: ip_sig,
    };
    let id_use_data = IdObjectUseData { aci, randomness };
    let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
    let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
    let policy = Policy {
        valid_to,
        created_at,
        policy_vec: {
            let mut tree = BTreeMap::new();
            tree.insert(AttributeTag::from(8u8), AttributeKind::from(31));
            tree
        },
        _phantom: Default::default(),
    };
    let acc_data = AccountData {
        keys: {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
            keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));
            keys
        },
        existing: Left(SignatureThreshold(2)),
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
    let cdi_check = verify_cdi(&global_ctx, &ip_info, None, &cdi);
    assert_eq!(cdi_check, Ok(()));

    // Verify serialization
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

    // Revoking anonymity using all but one AR
    let mut shares = Vec::new();
    for i in 0..(num_ars - 1) {
        let ar = cdi
            .values
            .ar_data
            .iter()
            .find(|&x| x.ar_identity == ArIdentity(i as u32))
            .unwrap();
        let decrypted_share = (
            ar.id_cred_pub_share_number.into(),
            ar_keys[i as usize].decrypt(&ar.enc_id_cred_pub_share),
        );
        shares.push(decrypted_share);
    }
    let revealed_id_cred_pub = reveal_id_cred_pub(&shares);
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

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
pub fn run_pipeline_wasm() {}

#[test]
pub fn run_pipeline() {
    test_pipeline();
}
