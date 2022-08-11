use crate::{
    account_holder::*,
    anonymity_revoker::*,
    chain::*,
    constants::{ArCurve, BaseField, IpPairing, *},
    identity_provider::*,
    secret_sharing::Threshold,
    types::*,
};
use crypto_common::{
    types::{KeyIndex, KeyPair, TransactionTime},
    *,
};
use curve_arithmetic::Curve;
use dodis_yampolskiy_prf as prf;
use ed25519_dalek as ed25519;
use either::Either::Left;
use elgamal::{PublicKey, SecretKey};
use rand::*;
use std::{collections::BTreeMap, convert::TryFrom};

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<BaseField, ExampleAttribute>;

pub const EXPIRY: TransactionTime = TransactionTime {
    seconds: 111111111111111111,
};

/// Create #num_ars anonymity revokers to be used by test
pub fn test_create_ars<T: Rng>(
    ar_base: &ArCurve,
    num_ars: u8,
    csprng: &mut T,
) -> (
    BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    BTreeMap<ArIdentity, SecretKey<ArCurve>>,
) {
    let mut ar_infos = BTreeMap::new();
    let mut ar_keys = BTreeMap::new();
    for i in 1..=num_ars {
        let ar_id = ArIdentity::new(i as u32);
        let ar_secret_key = SecretKey::generate(ar_base, csprng);
        let ar_public_key = PublicKey::from(&ar_secret_key);
        let ar_info = ArInfo::<ArCurve> {
            ar_identity: ar_id,
            ar_description: Description {
                name:        format!("AnonymityRevoker{}", i),
                url:         format!("AnonymityRevoker{}.com", i),
                description: format!("AnonymityRevoker{}", i),
            },
            ar_public_key,
        };
        let _ = ar_infos.insert(ar_id, ar_info);
        let _ = ar_keys.insert(ar_id, ar_secret_key);
    }
    (ar_infos, ar_keys)
}

/// Create identity provider with #num_ars ARs to be used by tests
pub fn test_create_ip_info<T: Rng + rand_core::CryptoRng>(
    csprng: &mut T,
    num_ars: u8,
    max_attrs: u8,
) -> IpData<IpPairing> {
    // Create key for IP long enough to encode the attributes and anonymity
    // revokers.
    let ps_len = (5 + num_ars + max_attrs) as usize;
    let ip_secret_key = ps_sig::SecretKey::<IpPairing>::generate(ps_len, csprng);
    let ip_verify_key = ps_sig::PublicKey::from(&ip_secret_key);
    let keypair = ed25519::Keypair::generate(csprng);
    let ip_cdi_verify_key = keypair.public;
    let ip_cdi_secret_key = keypair.secret;

    // Return IpData with public and private keys.
    IpData {
        public_ip_info: IpInfo {
            ip_identity: IpIdentity(0),
            ip_description: Description {
                name:        "IP0".to_owned(),
                url:         "IP0.com".to_owned(),
                description: "IP0".to_owned(),
            },
            ip_verify_key,
            ip_cdi_verify_key,
        },
        ip_secret_key,
        ip_cdi_secret_key,
    }
}

/// Create random AccCredentialInfo (ACI) to be used by tests
pub fn test_create_aci<T: Rng>(csprng: &mut T) -> AccCredentialInfo<ArCurve> {
    let ah_info = CredentialHolderInfo::<ArCurve> {
        id_cred: IdCredentials::generate(csprng),
    };

    let prf_key = prf::SecretKey::generate(csprng);
    AccCredentialInfo {
        cred_holder_info: ah_info,
        prf_key,
    }
}

/// Create random IdObjectUseData to be used by tests
pub fn test_create_id_use_data<T: Rng>(csprng: &mut T) -> IdObjectUseData<IpPairing, ArCurve> {
    let aci = test_create_aci(csprng);
    let randomness = ps_sig::SigRetrievalRandomness::generate_non_zero(csprng);
    IdObjectUseData { aci, randomness }
}

pub fn test_create_pio<'a>(
    id_use_data: &IdObjectUseData<IpPairing, ArCurve>,
    ip_info: &'a IpInfo<IpPairing>,
    ars_infos: &'a BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    global_ctx: &'a GlobalContext<ArCurve>,
    num_ars: u8, // should be at least 1
    initial_account_data: &InitialAccountData,
) -> (
    IpContext<'a, IpPairing, ArCurve>,
    PreIdentityObject<IpPairing, ArCurve>,
    ps_sig::SigRetrievalRandomness<IpPairing>,
) {
    // Create context with all anonymity revokers
    let context = IpContext::new(ip_info, ars_infos, global_ctx);

    // Select all ARs except last one
    let threshold = Threshold::try_from(num_ars - 1).unwrap_or(Threshold(1));

    // Create and return PIO
    let (pio, randomness) = generate_pio(&context, threshold, id_use_data, initial_account_data)
        .expect("Generating the pre-identity object should succeed.");
    (context, pio, randomness)
}

pub fn test_create_pio_v1<'a>(
    id_use_data: &IdObjectUseData<IpPairing, ArCurve>,
    ip_info: &'a IpInfo<IpPairing>,
    ars_infos: &'a BTreeMap<ArIdentity, ArInfo<ArCurve>>,
    global_ctx: &'a GlobalContext<ArCurve>,
    num_ars: u8, // should be at least 1
) -> (
    IpContext<'a, IpPairing, ArCurve>,
    PreIdentityObjectV1<IpPairing, ArCurve>,
    ps_sig::SigRetrievalRandomness<IpPairing>,
) {
    // Create context with all anonymity revokers
    let context = IpContext::new(ip_info, ars_infos, global_ctx);

    // Select all ARs except last one
    let threshold = Threshold::try_from(num_ars - 1).unwrap_or(Threshold(1));

    // Create and return PIO
    let (pio, randomness) = generate_pio_v1(&context, threshold, id_use_data)
        .expect("Generating the pre-identity object should succeed.");
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
        max_accounts: 237,
        alist,
        _phantom: Default::default(),
    }
}

#[test]
pub fn test_pipeline() {
    let mut csprng = thread_rng();

    // Generate PIO
    let max_attrs = 10;
    let num_ars = 5;
    let IpData {
        public_ip_info: ip_info,
        ip_secret_key,
        ip_cdi_secret_key,
    } = test_create_ip_info(&mut csprng, num_ars, max_attrs);

    let global_ctx = GlobalContext::generate(String::from("genesis_string"));

    let (ars_infos, ars_secret) =
        test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);

    let id_use_data = test_create_id_use_data(&mut csprng);
    let acc_data = InitialAccountData {
        keys:      {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
            keys
        },
        threshold: SignatureThreshold(2),
    };
    let (context, pio, _) = test_create_pio(
        &id_use_data,
        &ip_info,
        &ars_infos,
        &global_ctx,
        num_ars,
        &acc_data,
    );
    let alist = test_create_attributes();
    let ver_ok = verify_credentials(
        &pio,
        context,
        &alist,
        EXPIRY,
        &ip_secret_key,
        &ip_cdi_secret_key,
    );
    assert!(ver_ok.is_ok(), "Signature on the credential is invalid.");

    // Generate CDI
    let (ip_sig, initial_cdi) = ver_ok.unwrap();
    let cdi_check = verify_initial_cdi(&ip_info, &initial_cdi, EXPIRY);
    assert_eq!(cdi_check, Ok(()));
    let initial_cdi_values = serialize_deserialize(&initial_cdi.values);
    assert!(
        initial_cdi_values.is_ok(),
        "INITIAL VALUES Deserialization must be successful."
    );
    let initial_cdi_sig = serialize_deserialize(&initial_cdi.sig);
    assert!(
        initial_cdi_sig.is_ok(),
        "Signature deserialization must be successful."
    );
    let des_initial = serialize_deserialize(&initial_cdi);
    assert!(des_initial.is_ok(), "Deserialization must be successful.");

    let id_object = IdentityObject {
        pre_identity_object: pio,
        alist,
        signature: ip_sig,
    };
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
    let acc_data = CredentialData {
        keys:      {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
            keys
        },
        threshold: SignatureThreshold(2),
    };
    let (cdi, _) = create_credential(
        context,
        &id_object,
        &id_use_data,
        0,
        policy.clone(),
        &acc_data,
        &SystemAttributeRandomness {},
        &Left(EXPIRY),
    )
    .expect("Should generate the credential successfully.");
    let cdi_check = verify_cdi(&global_ctx, &ip_info, &ars_infos, &cdi, &Left(EXPIRY));
    assert_eq!(cdi_check, Ok(()));

    // Verify serialization
    let cdi_values = serialize_deserialize(&cdi.values);
    assert!(
        cdi_values.is_ok(),
        "VALUES Deserialization must be successful."
    );

    let cdi_commitments = serialize_deserialize(&cdi.proofs.id_proofs.commitments);
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
        des.unwrap().proofs.id_proofs.proof_reg_id,
        cdi.proofs.id_proofs.proof_reg_id,
        "It should deserialize back to what we started with."
    );

    // Revoking anonymity using all but one AR
    let mut shares = Vec::new();
    for (ar_id, key) in ars_secret.iter().skip(1) {
        let ar = cdi
            .values
            .ar_data
            .get(ar_id)
            .unwrap_or_else(|| panic!("Anonymity revoker {} is not present.", ar_id));
        let decrypted_share = (*ar_id, key.decrypt(&ar.enc_id_cred_pub_share));
        shares.push(decrypted_share);
    }
    let revealed_id_cred_pub = reveal_id_cred_pub(&shares);
    assert_eq!(
        revealed_id_cred_pub,
        global_ctx
            .on_chain_commitment_key
            .g
            .mul_by_scalar(&id_use_data.aci.cred_holder_info.id_cred.id_cred_sec)
    );

    // generate a new cdi from a modified pre-identity object in which we swapped
    // two anonymity revokers. Verification of this credential should fail the
    // signature at the very least.
    let (mut cdi, _) = create_credential(
        context,
        &id_object,
        &id_use_data,
        0,
        policy,
        &acc_data,
        &SystemAttributeRandomness {},
        &Left(EXPIRY),
    )
    .expect("Should generate the credential successfully.");
    // Swap two ar_data values for two anonymity revokers.
    let x_2 = cdi
        .values
        .ar_data
        .get(&ArIdentity::new(2))
        .expect("AR 2 exists")
        .clone();
    let x_3 = cdi
        .values
        .ar_data
        .get(&ArIdentity::new(3))
        .expect("AR 3 exists")
        .clone();
    *cdi.values
        .ar_data
        .get_mut(&ArIdentity::new(2))
        .expect("AR 2 exists") = x_3;
    *cdi.values
        .ar_data
        .get_mut(&ArIdentity::new(3))
        .expect("AR 2 exists") = x_2;
    // Verification should now fail.
    let cdi_check = verify_cdi(&global_ctx, &ip_info, &ars_infos, &cdi, &Left(EXPIRY));
    assert_ne!(cdi_check, Ok(()));
}

#[test]
pub fn test_pipeline_v1() {
    let mut csprng = thread_rng();

    // Generate PIO
    let max_attrs = 10;
    let num_ars = 5;
    let IpData {
        public_ip_info: ip_info,
        ip_secret_key,
        ..
    } = test_create_ip_info(&mut csprng, num_ars, max_attrs);

    let global_ctx = GlobalContext::generate(String::from("genesis_string"));

    let (ars_infos, ars_secret) =
        test_create_ars(&global_ctx.on_chain_commitment_key.g, num_ars, &mut csprng);

    let id_use_data = test_create_id_use_data(&mut csprng);
    let (context, pio, randomness) =
        test_create_pio_v1(&id_use_data, &ip_info, &ars_infos, &global_ctx, num_ars);
    assert!(
        *randomness == *id_use_data.randomness,
        "Returned randomness is not equal to used randomness."
    );
    let alist = test_create_attributes();
    let ver_ok = verify_credentials_v1(&pio, context, &alist, &ip_secret_key);
    assert!(ver_ok.is_ok(), "Signature on the credential is invalid.");

    // Generate CDI
    let ip_sig = ver_ok.unwrap();

    let id_object = IdentityObjectV1 {
        pre_identity_object: pio,
        alist,
        signature: ip_sig,
    };
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
    let acc_data = CredentialData {
        keys:      {
            let mut keys = BTreeMap::new();
            keys.insert(KeyIndex(0), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(1), KeyPair::generate(&mut csprng));
            keys.insert(KeyIndex(2), KeyPair::generate(&mut csprng));
            keys
        },
        threshold: SignatureThreshold(2),
    };
    let (cdi, _) = create_credential(
        context,
        &id_object,
        &id_use_data,
        0,
        policy.clone(),
        &acc_data,
        &SystemAttributeRandomness {},
        &Left(EXPIRY),
    )
    .expect("Should generate the credential successfully.");
    let cdi_check = verify_cdi(&global_ctx, &ip_info, &ars_infos, &cdi, &Left(EXPIRY));
    assert_eq!(cdi_check, Ok(()));

    // Verify serialization
    let cdi_values = serialize_deserialize(&cdi.values);
    assert!(
        cdi_values.is_ok(),
        "VALUES Deserialization must be successful."
    );

    let cdi_commitments = serialize_deserialize(&cdi.proofs.id_proofs.commitments);
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
        des.unwrap().proofs.id_proofs.proof_reg_id,
        cdi.proofs.id_proofs.proof_reg_id,
        "It should deserialize back to what we started with."
    );

    // Revoking anonymity using all but one AR
    let mut shares = Vec::new();
    for (ar_id, key) in ars_secret.iter().skip(1) {
        let ar = cdi
            .values
            .ar_data
            .get(ar_id)
            .unwrap_or_else(|| panic!("Anonymity revoker {} is not present.", ar_id));
        let decrypted_share = (*ar_id, key.decrypt(&ar.enc_id_cred_pub_share));
        shares.push(decrypted_share);
    }
    let revealed_id_cred_pub = reveal_id_cred_pub(&shares);
    assert_eq!(
        revealed_id_cred_pub,
        global_ctx
            .on_chain_commitment_key
            .g
            .mul_by_scalar(&id_use_data.aci.cred_holder_info.id_cred.id_cred_sec)
    );

    // generate a new cdi from a modified pre-identity object in which we swapped
    // two anonymity revokers. Verification of this credential should fail the
    // signature at the very least.
    let (mut cdi, _) = create_credential(
        context,
        &id_object,
        &id_use_data,
        0,
        policy,
        &acc_data,
        &SystemAttributeRandomness {},
        &Left(EXPIRY),
    )
    .expect("Should generate the credential successfully.");
    // Swap two ar_data values for two anonymity revokers.
    let x_2 = cdi
        .values
        .ar_data
        .get(&ArIdentity::new(2))
        .expect("AR 2 exists")
        .clone();
    let x_3 = cdi
        .values
        .ar_data
        .get(&ArIdentity::new(3))
        .expect("AR 3 exists")
        .clone();
    *cdi.values
        .ar_data
        .get_mut(&ArIdentity::new(2))
        .expect("AR 2 exists") = x_3;
    *cdi.values
        .ar_data
        .get_mut(&ArIdentity::new(3))
        .expect("AR 2 exists") = x_2;
    // Verification should now fail.
    let cdi_check = verify_cdi(&global_ctx, &ip_info, &ars_infos, &cdi, &Left(EXPIRY));
    assert_ne!(cdi_check, Ok(()));
}
