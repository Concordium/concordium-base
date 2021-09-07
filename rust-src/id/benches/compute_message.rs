use criterion::*;
use curve_arithmetic::*;
use id::identity_provider::compute_message;
use pairing::bls12_381::G1;
use rand::*;
use pedersen_scheme::Commitment;
use id::secret_sharing::Threshold;
use id::types::*;
use std::convert::TryFrom;
// use id::types::ArIdentity::*;
use std::collections::{BTreeSet, BTreeMap};
use pairing::bls12_381::*;

fn bench_compute_message(c: &mut Criterion) {
    let mut csprng = thread_rng();

    // todo is zero okay for testing?
    let comm1 = Commitment(G1::zero_point());
    let comm2 = Commitment(G1::zero_point());
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
    
    type ExampleAttributeList = AttributeList<id::constants::BaseField, id::constants::AttributeKind>;
    let alist: BTreeMap<AttributeTag, id::constants::AttributeKind> = BTreeMap::new();
    // todo add a typical amount of attributes
    // alist.insert(key: K, value: V) todo what/how many should be added?
    let att_list = ExampleAttributeList {
        valid_to:     valid_to_next_year,
        created_at:   now,
        alist:        alist,
        max_accounts: 200,
        _phantom:     Default::default(),
    };
    // todo how many scalars?
    let public_key : ps_sig::PublicKey<Bls12> = ps_sig::PublicKey::arbitrary(2, &mut csprng); 

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