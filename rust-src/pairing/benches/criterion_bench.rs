// Benches using criterion for hashing to group elements
// See folder bls12_381 for all the benches, including
// the ones here

#[macro_use]
extern crate criterion;
extern crate rand;

extern crate pairing;
use pairing::{
    bls12_381::{G1Affine, G1},
    CurveAffine, CurveProjective,
};

use criterion::Criterion;
use rand::{Rng, SeedableRng, XorShiftRng};

fn bench_hash_to_g1(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let v_: Vec<[u8; 32]> = (0..SAMPLES).map(|_| rng.gen::<[u8; 32]>()).collect();
    let v = v_.clone();
    c.bench_function("hash_to_g1", move |b| {
        let mut count = 0;
        b.iter(|| {
            let _ = <G1 as CurveProjective>::hash_to_group_element(&v[count]);
            count = (count + 1) % SAMPLES;
        });
    });

    let v = v_.clone();
    c.bench_function("hash_to_g1affine", move |b| {
        let mut count = 0;
        b.iter(|| {
            let _ = <G1Affine as CurveAffine>::hash_to_group_element(&v[count]);
            count = (count + 1) % SAMPLES;
        });
    });
}

criterion_group!(hash_to_g1, bench_hash_to_g1);
criterion_main!(hash_to_g1);
