use criterion::*;
use curve_arithmetic::*;
use id::identity_provider::compute_message;
use pairing::bls12_381::G1;
use rand::*;
use pedersen_scheme::Commitment;
use id::secret_sharing::Threshold;
use id::types::*;
use std::convert::TryFrom;
use std::collections::{BTreeSet, BTreeMap};
use pairing::bls12_381::*;
use serde_json::from_str;

fn bench_compute_message(c: &mut Criterion) {
    let mut csprng = thread_rng();

    let comm1 = Commitment(G1::generate(&mut csprng));
    let comm2 = Commitment(G1::generate(&mut csprng));

    //The usual setting at the moment is 2 out of 3 anonymity revokers
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
    type ExampleAttributeList = AttributeList<id::constants::BaseField, id::constants::AttributeKind>;
    let alist: BTreeMap<AttributeTag, id::constants::AttributeKind> = from_str(aliststr).unwrap();

    // the number of scalars in the pk should be equal to the total number of attributes, 
    // including mandatory attributes: i.e. `valid_to` etc.
    let public_key : ps_sig::PublicKey<Bls12> = ps_sig::PublicKey::arbitrary(alist.len() + 3, &mut csprng); 

    let att_list = ExampleAttributeList {
        valid_to:     valid_to_next_year,
        created_at:   now,
        alist:        alist,
        max_accounts: 200,
        _phantom:     Default::default(),
    };

    c.bench_function("Compute message", move |b| {
        b.iter(|| compute_message(
            &comm1,
            &comm2,
            threshold,
            &ar_list,
            &att_list,
            &public_key
        ))
    });
}

criterion_group!(compute_message_benchmarks, bench_compute_message);
criterion_main!(compute_message_benchmarks);