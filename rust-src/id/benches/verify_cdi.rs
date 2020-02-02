use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519 as ed25519;
use elgamal::{public::PublicKey, secret::SecretKey};
use id::{
    account_holder::*, chain::*, ffi::*, identity_provider::*, secret_sharing::Threshold, types::*,
};

use pairing::bls12_381::{Bls12, G1};
use ps_sig;

use rand::*;

use pedersen_scheme::{key as pedersen_key, Value as PedersenValue};
use std::collections::BTreeMap;

use std::io::Cursor;

use criterion::*;

type ExampleCurve = G1;

type ExampleAttribute = AttributeKind;

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, ExampleAttribute>;

pub fn setup() -> (
    GlobalContext<ExampleCurve>,
    IpInfo<Bls12, ExampleCurve>,
    CredDeploymentInfo<Bls12, ExampleCurve, ExampleAttribute>,
) {
    let mut csprng = thread_rng();

    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let public = ExampleCurve::one_point().mul_by_scalar(&secret);
    let ah_info = CredentialHolderInfo::<ExampleCurve> {
        id_ah:   "ACCOUNT_HOLDER".to_owned(),
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue { value: secret },
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
        cred_holder_info: ah_info,
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
        policy_vec: {
            let mut tree = BTreeMap::new();
            tree.insert(1u16, AttributeKind::from(31));
            tree
        },
        _phantom: Default::default(),
    };

    let kp = ed25519::Keypair::generate(&mut csprng);
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

    assert!(
        verify_cdi(&global_ctx, &ip_info, &cdi).is_ok(),
        "Make sure the credential is valid!"
    );
    (global_ctx, ip_info, cdi)
}

pub fn bench_verify_with_serialize(c: &mut Criterion) {
    let (global_ctx, ip_info, cdi) = setup();

    let bytes = cdi.to_bytes();

    let bench_with_serialize = move |b: &mut Bencher| {
        b.iter(|| {
            let des = CredDeploymentInfo::<Bls12, ExampleCurve, ExampleAttribute>::from_bytes(
                &mut Cursor::new(&bytes),
            )
            .unwrap();
            verify_cdi(&global_ctx, &ip_info, &des)
        })
    };
    c.bench_function("Verify CDI with serialization", bench_with_serialize);
}

pub fn bench_verify_without_serialize(c: &mut Criterion) {
    let (global_ctx, ip_info, cdi) = setup();

    let bench_without_serialize =
        move |b: &mut Bencher| b.iter(|| verify_cdi(&global_ctx, &ip_info, &cdi));

    c.bench_function("Verify CDI without serialization", bench_without_serialize);
}

criterion_group! {
    name = verify_cdi_benches;
    config = Criterion::default();
    targets =
        bench_verify_with_serialize,
        bench_verify_without_serialize
}

criterion_main!(verify_cdi_benches);
