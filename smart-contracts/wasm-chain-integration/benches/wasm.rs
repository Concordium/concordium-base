use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use wasm_chain_integration::{ConcordiumAllowedImports, ProcessedImports};
use wasm_transform::*;

static CONTRACT_BYTES_SIMPLE_GAME: &[u8] = include_bytes!("./simple_game.wasm");
static CONTRACT_BYTES_COUNTER: &[u8] = include_bytes!("./counter.wasm");

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Module processing simple_game");

    group.measurement_time(Duration::from_secs(10));

    group.bench_function("validate", |b| {
        b.iter(|| {
            let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_SIMPLE_GAME)).unwrap();
            assert!(
                validate::validate_module(&ConcordiumAllowedImports, &skeleton).is_ok(),
                "Cannot validate module."
            )
        })
    });

    group.bench_function("validate + inject metering", |b| {
        b.iter(move || {
            let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_SIMPLE_GAME)).unwrap();
            let mut module =
                validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
            assert!(module.inject_metering().is_ok(), "Metering injection failed.")
        })
    });

    group.bench_function("validate + inject metering + compile", |b| {
        b.iter(move || {
            let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_SIMPLE_GAME)).unwrap();
            let mut module =
                validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
            module.inject_metering().unwrap();
            assert!(module.compile::<ProcessedImports>().is_ok(), "Compilation failed.")
        })
    });

    group.finish();

    let mut group = c.benchmark_group("Module processing counter_game");

    group.measurement_time(Duration::from_secs(10));

    group.bench_function("validate", |b| {
        b.iter(|| {
            let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_COUNTER)).unwrap();
            assert!(
                validate::validate_module(&ConcordiumAllowedImports, &skeleton).is_ok(),
                "Cannot validate module."
            )
        })
    });

    group.bench_function("validate + inject metering", |b| {
        b.iter(move || {
            let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_COUNTER)).unwrap();
            let mut module =
                validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
            assert!(module.inject_metering().is_ok(), "Metering injection failed.")
        })
    });

    group.bench_function("validate + inject metering + compile", |b| {
        b.iter(move || {
            let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_COUNTER)).unwrap();
            let mut module =
                validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
            module.inject_metering().unwrap();
            assert!(module.compile::<ProcessedImports>().is_ok(), "Compilation failed.")
        })
    });

    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
