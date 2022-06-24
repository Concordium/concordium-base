use criterion::*;
use crypto_common::types::*;
use curve_arithmetic::*;
use id::{
    constants::*,
    identity_provider::{compute_message, sign_identity_object, validate_request},
    secret_sharing::Threshold,
    test::*,
    types::*,
};
use pairing::bls12_381::{G1, *};
use pedersen_scheme::Commitment;
use rand::*;
use serde_json::from_str;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
};

fn bench_compute_message(c: &mut Criterion) {
    let mut csprng = thread_rng();

    let comm1 = Commitment(G1::generate(&mut csprng));
    let comm2 = Commitment(G1::generate(&mut csprng));

    // The usual setting at the moment is 2 out of 3 anonymity revokers
    let threshold = Threshold(2);

    // add 3 anonymity revokers
    let mut ar_list: BTreeSet<ArIdentity> = BTreeSet::new();
    ar_list.insert(ArIdentity::try_from(1).unwrap());
    ar_list.insert(ArIdentity::try_from(2).unwrap());
    ar_list.insert(ArIdentity::try_from(3).unwrap());

    let now = YearMonth::now();
    let valid_to_next_year = YearMonth {
        year:  now.year + 1,
        month: now.month,
    };

    // an example map of attributes from documentation:
    let aliststr = r#"{
        "countryOfResidence": "DE",
        "dob": "19700101",
        "firstName": "John",
        "idDocExpiresAt": "20291231",
        "idDocIssuedAt": "20200401",
        "idDocIssuer": "DK",
        "idDocNo": "1234567890",
        "idDocType": "1",
        "lastName": "Doe",
        "nationality": "DK",
        "sex": "1"
    }"#;
    type ExampleAttributeList =
        AttributeList<id::constants::BaseField, id::constants::AttributeKind>;
    let alist: BTreeMap<AttributeTag, id::constants::AttributeKind> = from_str(aliststr).unwrap();

    // the number of scalars in the pk should be at least the total number of
    // attributes, including mandatory attributes: i.e. `valid_to` etc.
    let public_key: ps_sig::PublicKey<Bls12> =
        ps_sig::PublicKey::arbitrary(alist.len() + 3, &mut csprng);

    let att_list = ExampleAttributeList {
        valid_to: valid_to_next_year,
        created_at: now,
        alist,
        max_accounts: 200,
        _phantom: Default::default(),
    };

    c.bench_function("Compute message", move |b| {
        b.iter(|| compute_message(&comm1, &comm2, threshold, &ar_list, &att_list, &public_key))
    });
}

fn bench_validate_request(c: &mut Criterion) {
    // Arrange (create identity provider and PreIdentityObject, and verify validity)
    let max_attrs = 10;
    let num_ars = 4;
    let mut csprng = thread_rng();
    let IpData {
        public_ip_info: ip_info,
        ip_secret_key: _,
        ip_cdi_secret_key: _,
    } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
    let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
    let (ars_infos, _) =
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

    // Act
    c.bench_function("Validate request", move |b| {
        b.iter(|| validate_request(&pio, context))
    });
}

fn bench_sign_identity_object(c: &mut Criterion) {
    // Arrange (create identity provider and PreIdentityObject, and verify validity)
    let max_attrs = 10;
    let num_ars = 4;
    let mut csprng = thread_rng();
    let IpData {
        public_ip_info: ip_info,
        ip_secret_key,
        ip_cdi_secret_key: _,
    } = test_create_ip_info(&mut csprng, num_ars, max_attrs);
    let global_ctx = GlobalContext::<ArCurve>::generate(String::from("genesis_string"));
    let (ars_infos, _) =
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
    let attrs = test_create_attributes();

    // Act
    c.bench_function("Sign identity object", move |b| {
        b.iter(|| sign_identity_object(&pio, &context.ip_info, &attrs, &ip_secret_key))
    });
}

criterion_group!(
    compute_message_benchmarks,
    bench_compute_message,
    bench_validate_request,
    bench_sign_identity_object
);
criterion_main!(compute_message_benchmarks);
