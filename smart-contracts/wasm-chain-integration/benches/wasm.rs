use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use wasm_chain_integration::{ConcordiumAllowedImports, ProcessedImports, TestHost};
use wasm_transform::{artifact::ArtifactNamedImport, machine::Value, *};

static CONTRACT_BYTES_SIMPLE_GAME: &[u8] = include_bytes!("./simple_game.wasm");
static CONTRACT_BYTES_COUNTER: &[u8] = include_bytes!("./counter.wasm");
static CONTRACT_BYTES_MINIMAL: &[u8] = include_bytes!("./code/minimal.wasm");
static CONTRACT_BYTES_INSTRUCTIONS: &[u8] = include_bytes!("./code/instruction.wasm");
static CONTRACT_BYTES_MEMORY_INSTRUCTIONS: &[u8] = include_bytes!("./code/memory-instruction.wasm");

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("Module processing simple_game");

        group.measurement_time(Duration::from_secs(10));

        group.bench_function("validate", |b| {
            b.iter(|| {
                let skeleton =
                    parse::parse_skeleton(black_box(CONTRACT_BYTES_SIMPLE_GAME)).unwrap();
                assert!(
                    validate::validate_module(&ConcordiumAllowedImports, &skeleton).is_ok(),
                    "Cannot validate module."
                )
            })
        });

        group.bench_function("validate + inject metering", |b| {
            b.iter(move || {
                let skeleton =
                    parse::parse_skeleton(black_box(CONTRACT_BYTES_SIMPLE_GAME)).unwrap();
                let mut module =
                    validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
                assert!(module.inject_metering().is_ok(), "Metering injection failed.")
            })
        });

        group.bench_function("validate + inject metering + compile", |b| {
            b.iter(move || {
                let skeleton =
                    parse::parse_skeleton(black_box(CONTRACT_BYTES_SIMPLE_GAME)).unwrap();
                let mut module =
                    validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
                module.inject_metering().unwrap();
                assert!(module.compile::<ProcessedImports>().is_ok(), "Compilation failed.")
            })
        });

        group.finish();
    }
    {
        let mut group = c.benchmark_group("Module processing minimal module");

        group.measurement_time(Duration::from_secs(10));

        group.bench_function("validate", |b| {
            b.iter(|| {
                let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_MINIMAL)).unwrap();
                if let Err(e) = validate::validate_module(&ConcordiumAllowedImports, &skeleton) {
                    panic!("{}", e)
                }
            })
        });

        group.bench_function("validate + inject metering", |b| {
            b.iter(move || {
                let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_MINIMAL)).unwrap();
                let mut module =
                    validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
                assert!(module.inject_metering().is_ok(), "Metering injection failed.")
            })
        });

        group.bench_function("validate + inject metering + compile", |b| {
            b.iter(move || {
                let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_MINIMAL)).unwrap();
                let mut module =
                    validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
                module.inject_metering().unwrap();
                assert!(module.compile::<ProcessedImports>().is_ok(), "Compilation failed.")
            })
        });

        group.finish();
    }

    {
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

        group.finish();
    }

    {
        let mut group = c.benchmark_group("Instruction execution");

        group.measurement_time(Duration::from_secs(20));

        let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_INSTRUCTIONS)).unwrap();
        let module = validate::validate_module(&TestHost, &skeleton).unwrap();
        let artifact = module.compile::<ArtifactNamedImport>().unwrap();
        for n in [0, 1, 10000, 100000, 200000].iter() {
            group.bench_with_input(format!("execute n = {}", n), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact.run(&mut TestHost, "foo_extern", &[Value::I64(*m)]).is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        let skeleton =
            parse::parse_skeleton(black_box(CONTRACT_BYTES_MEMORY_INSTRUCTIONS)).unwrap();
        let module = validate::validate_module(&TestHost, &skeleton).unwrap();
        let artifact = module.compile::<ArtifactNamedImport>().unwrap();
        for n in [1, 10, 50, 100, 250, 500, 1000, 1024].iter() {
            group.bench_with_input(format!("allocate n = {} pages", n), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact.run(&mut TestHost, "foo_extern", &[Value::I32(*m)]).is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        // The -4 is because we write 4 bytes starting at the given location, which must
        // all fit into memory.
        for n in [0, 1000, 10000, 100000, 512 * 65536 - 4].iter() {
            group.bench_with_input(format!("write u32 n = {} times", n / 4), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact.run(&mut TestHost, "write_u32", &[Value::I32(*m)]).is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        // The -8 is because we write 8 bytes starting at the given location, which must
        // all fit into memory.
        for n in [0, 1000, 10000, 100000, 512 * 65536 - 8].iter() {
            group.bench_with_input(format!("write u64 n = {} times", n / 8), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact.run(&mut TestHost, "write_u64", &[Value::I32(*m)]).is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        // The -1 is because we write 1 byte starting at the given location, which must
        // fit into memory.
        for n in [0, 1000, 10000, 100000, 512 * 65536 - 1].iter() {
            group.bench_with_input(format!("write u8 n  = {} times as u32", n), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact.run(&mut TestHost, "write_u32_u8", &[Value::I32(*m)]).is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        // The -1 is because we write 1 byte starting at the given location, which must
        // fit into memory.
        for n in [0, 1000, 10000, 100000, 512 * 65536 - 1].iter() {
            group.bench_with_input(format!("write u8 n  = {} times as u64", n), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact.run(&mut TestHost, "write_u64_u8", &[Value::I32(*m)]).is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
