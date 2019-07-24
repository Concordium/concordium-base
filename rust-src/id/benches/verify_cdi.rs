use curve_arithmetic::{Curve, Pairing};
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519 as ed25519;
use elgamal::{public::PublicKey, secret::SecretKey};
use id::{account_holder::*, chain::*, ffi::*, identity_provider::*, types::*};
use pairing::bls12_381::{Bls12, G1};
use ps_sig;

use rand::*;

use pedersen_scheme::key as pedersen_key;

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
    let ah_info = CredentialHolderInfo::<ExampleCurve, ExampleCurve> {
        id_ah:   "ACCOUNT_HOLDER".to_owned(),
        id_cred: IdCredentials {
            id_cred_sec:    secret,
            id_cred_pub:    public,
            id_cred_pub_ip: public,
        },
    };

    let id_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(10, &mut csprng);
    let id_public_key = ps_sig::public::PublicKey::from(&id_secret_key);

    let ar_secret_key = SecretKey::generate(&mut csprng);
    let ar_public_key = PublicKey::from(&ar_secret_key);
    let ar_info = ArInfo {
        ar_name: "AR".to_owned(),
        ar_public_key,
        ar_elgamal_generator: PublicKey::generator(),
    };

    let ip_info = IpInfo {
        ip_identity: "ID".to_owned(),
        ip_verify_key: id_public_key,
        ar_info,
    };

    let prf_key = prf::SecretKey::generate(&mut csprng);

    let variant = 0;
    let expiry_date = 123123123;
    let alist = vec![AttributeKind::U16(55), AttributeKind::U8(31)];
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

    let context = make_context_from_ip_info(ip_info.clone());
    let (pio, randomness) = generate_pio(&context, &aci);

    let sig_ok = verify_credentials(&pio, context, &id_secret_key);

    // First test, check that we have a valid signature.
    assert!(sig_ok.is_ok());

    let ip_sig = sig_ok.unwrap();

    let global_ctx = GlobalContext {
        dlog_base_chain:         ExampleCurve::one_point(),
        on_chain_commitment_key: pedersen_key::CommitmentKey::generate(1, &mut csprng),
    };

    let policy = Policy {
        variant,
        expiry: expiry_date,
        policy_vec: vec![(1, AttributeKind::U8(31))],
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
