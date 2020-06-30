use crypto_common::*;
use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use elgamal::{public::PublicKey, secret::SecretKey};
use id::{
    account_holder::*, anonymity_revoker::*, chain::*, ffi::*, identity_provider::*,
    secret_sharing::Threshold, types::*,
};
use std::io::Cursor;

use pairing::bls12_381::{Bls12, G1};

use rand::*;

use pedersen_scheme::key as pedersen_key;
use std::collections::BTreeMap;

use either::Left;

use std::convert::TryFrom;

use criterion::*;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

fn bench_parts(c: &mut Criterion) {
    let mut csprng = thread_rng();

    let ip_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(20, &mut csprng);
    let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);

    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials::generate(&mut csprng),
    };

    let ar_base = ExampleCurve::generate(&mut csprng);

    let ar1_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar1_public_key = PublicKey::from(&ar1_secret_key);
    let ar1_info = ArInfo::<G1> {
        ar_identity:    ArIdentity::try_from(1).unwrap(),
        ar_description: mk_dummy_description("A good AR".to_string()),
        ar_public_key:  ar1_public_key,
    };

    let ar2_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar2_public_key = PublicKey::from(&ar2_secret_key);
    let ar2_info = ArInfo::<G1> {
        ar_identity:    ArIdentity::try_from(2).unwrap(),
        ar_description: mk_dummy_description("A nice AR".to_string()),
        ar_public_key:  ar2_public_key,
    };

    let ar3_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar3_public_key = PublicKey::from(&ar3_secret_key);
    let ar3_info = ArInfo::<G1> {
        ar_identity:    ArIdentity::try_from(3).unwrap(),
        ar_description: mk_dummy_description("Weird AR".to_string()),
        ar_public_key:  ar3_public_key,
    };

    let ar4_secret_key = SecretKey::generate(&ar_base, &mut csprng);
    let ar4_public_key = PublicKey::from(&ar4_secret_key);
    let ar4_info = ArInfo::<G1> {
        ar_identity:    ArIdentity::try_from(4).unwrap(),
        ar_description: mk_dummy_description("Ok AR".to_string()),
        ar_public_key:  ar4_public_key,
    };

    let ar_ck = pedersen_key::CommitmentKey::generate(&mut csprng);

    let ip_info = IpInfo {
        ip_identity:    IpIdentity(88),
        ip_description: mk_dummy_description("IP88".to_string()),
        ip_verify_key:  ip_public_key,
        ip_ars:         IpAnonymityRevokers {
            ars: vec![ar1_info, ar2_info, ar3_info, ar4_info],
            ar_cmm_key: ar_ck,
            ar_base,
        },
    };

    let prf_key = prf::SecretKey::generate(&mut csprng);

    let valid_to = YearMonth::new(2021, 1).unwrap();
    let created_at = YearMonth::new(2021, 1).unwrap();
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
        valid_to,
        created_at,
        max_accounts: 255,
        alist,
        _phantom: Default::default(),
    };

    let context = make_context_from_ip_info(ip_info.clone(), ChoiceArParameters {
        ar_identities: [
            ArIdentity::try_from(1).unwrap(),
            ArIdentity::try_from(2).unwrap(),
            ArIdentity::try_from(4).unwrap(),
        ]
        .iter()
        .copied()
        .collect(),
        threshold:     Threshold(2),
    })
    .expect("The constructed ARs are valid.");

    let (pio, randomness) =
        generate_pio(&context, &aci).expect("Generating the pre-identity object succeed.");
    let pio_ser = to_bytes(&pio);
    let ip_info_ser = to_bytes(&ip_info);
    let pio_des = from_bytes(&mut Cursor::new(&pio_ser)).unwrap();
    let ip_info_des = from_bytes(&mut Cursor::new(&ip_info_ser)).unwrap();
    let sig_ok =
        verify_credentials::<_, _, ExampleCurve>(&pio_des, &ip_info_des, &alist, &ip_secret_key);

    let ip_sig = sig_ok.unwrap();

    let global_ctx = GlobalContext {
        on_chain_commitment_key: pedersen_key::CommitmentKey::generate(&mut csprng),
    };

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

    let cdi = create_credential(
        &ip_info,
        &global_ctx,
        &id_object,
        &id_use_data,
        0,
        policy.clone(),
        &acc_data,
    )
    .expect("Should generate the credential successfully.");

    let ar_2 = ArIdentity::try_from(2).unwrap();

    // revoking anonymity
    let second_ar = cdi.values.ar_data.get(&ar_2).unwrap();
    let decrypted_share_ar2 = (
        ar_2,
        ar2_secret_key.decrypt(&second_ar.enc_id_cred_pub_share),
    );
    let ar_4 = ArIdentity::try_from(4).unwrap();
    let fourth_ar = cdi.values.ar_data.get(&ar_4).unwrap();
    let decrypted_share_ar4 = (
        ar_4,
        ar4_secret_key.decrypt(&fourth_ar.enc_id_cred_pub_share),
    );

    let bench_pio = move |b: &mut Bencher, x: &(_, _)| b.iter(|| generate_pio(x.0, x.1));
    c.bench_with_input(
        BenchmarkId::new("Generate ID request", ""),
        &(&context, &id_use_data.aci),
        bench_pio,
    );

    let bench_create_credential =
        move |b: &mut Bencher, x: &(_, _, _, _, _, Policy<ExampleCurve, AttributeKind>, _)| {
            b.iter(|| create_credential(x.0, x.1, x.2, x.3, x.4, x.5.clone(), x.6).unwrap())
        };
    c.bench_with_input(
        BenchmarkId::new("Generate CDI", ""),
        &(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_use_data,
            0,
            policy,
            &acc_data,
        ),
        bench_create_credential,
    );

    let bench_verify_cdi =
        move |b: &mut Bencher, x: &(_, _, _)| b.iter(|| verify_cdi(x.0, x.1, None, x.2).unwrap());
    c.bench_with_input(
        BenchmarkId::new("Verify CDI", ""),
        &(&global_ctx, &ip_info, &cdi),
        bench_verify_cdi,
    );
    let share_vec = vec![decrypted_share_ar2, decrypted_share_ar4];
    let bench_reveal_id_cred_pub = move |b: &mut Bencher| b.iter(|| reveal_id_cred_pub(&share_vec));
    let bench_verify_ip = move |b: &mut Bencher| {
        b.iter(|| {
            verify_credentials(
                &id_object.pre_identity_object,
                &ip_info,
                &id_object.alist,
                &ip_secret_key,
            )
            .unwrap()
        })
    };

    c.bench_function("IP verify credentials", bench_verify_ip);
    c.bench_function("Reveal IdCredPub", bench_reveal_id_cred_pub);
}

criterion_group! {
    name = verify_id_interactions;
    config = Criterion::default();
    targets =
        bench_parts
}

criterion_main!(verify_id_interactions);
