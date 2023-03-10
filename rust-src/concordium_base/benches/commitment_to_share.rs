use criterion::*;
use curve_arithmetic::*;
use id::utils::commitment_to_share;
use pairing::bls12_381::G1;
use pedersen_scheme::Commitment;
use rand::*;

fn bench_commitment_to_share(c: &mut Criterion) {
    let mut csprng = thread_rng();

    // Typical number of commitments should be 3-4
    // Benchmarking for 4 commitments
    let number_of_commitments = 4;
    let share_number = G1::generate_scalar(&mut csprng);
    let mut coeff_commitments = Vec::with_capacity(number_of_commitments);
    for _ in 0..number_of_commitments {
        coeff_commitments.push(Commitment(G1::generate(&mut csprng)));
    }
    c.bench_function("Commitment to share", move |b| {
        b.iter(|| commitment_to_share(&share_number, &coeff_commitments[..]))
    });
}

criterion_group!(commitment_to_share_benchmarks, bench_commitment_to_share);
criterion_main!(commitment_to_share_benchmarks);
