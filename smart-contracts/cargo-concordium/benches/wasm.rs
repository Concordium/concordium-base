#[macro_use]
extern crate criterion;

use contracts_common::*;
use criterion::Criterion;
use wasmer_interp::*;
use wasmer_runtime::{compile, func, imports, instantiate};
use wasmer_runtime_core::validate;

static WASM: &[u8] = include_bytes!("artifacts/counter.wasm");

#[cfg(feature = "cranelift")]
const BACKEND: wasmer_runtime::Backend = wasmer_runtime::Backend::Cranelift;
#[cfg(feature = "singlepass")]
const BACKEND: wasmer_runtime::Backend = wasmer_runtime::Backend::Singlepass;

pub fn bench_instantiate(c: &mut Criterion) {
    let (import_obj, _, _, _, _) = make_imports(
        Which::Init {
            init_ctx: &InitContext {
                init_origin: AccountAddress([0u8; 32]),
                metadata:    ChainMetadata {
                    slot_number:      0,
                    block_height:     0,
                    finalized_height: 0,
                    slot_time:        0,
                },
            },
        },
        Vec::new(),
        1000_000_000,
    );

    c.bench_function("instantiate_from_bytes", move |b| b.iter(|| instantiate(WASM, &import_obj)));

    c.bench_function("compile_from_bytes", move |b| b.iter(|| compile(WASM)));

    c.bench_function("validate_from_bytes", move |b| b.iter(|| assert!(validate(WASM))));

    let module = compile(WASM).expect("Compilation should succeed.");

    c.bench_function("make_artifact_from_module", move |b| {
        b.iter(|| {
            module.cache().expect("Could not make a cache.");
        })
    });

    let module = compile(WASM).expect("Compilation should succeed.");
    let artifact = module.cache().expect("Could not make a cache.");
    let bytes = artifact.serialize().expect("Should be able to serialize bytes");

    c.bench_function("load_module_from_cache", move |b| {
        b.iter(|| {
            let artifact = module.cache().expect("Could not make a cache.");
            unsafe {
                wasmer_runtime_core::load_cache_with(
                    artifact,
                    &*wasmer_runtime::compiler_for_backend(BACKEND).unwrap(),
                )
                .unwrap()
            }
        });
    });

    c.bench_function("load_module_from_bytes", move |b| {
        b.iter(|| {
            let artifact = wasmer_runtime_core::cache::Artifact::deserialize(&bytes)
                .expect("Should be able to deserialize");
            unsafe {
                wasmer_runtime_core::load_cache_with(
                    artifact,
                    &*wasmer_runtime::compiler_for_backend(BACKEND).unwrap(),
                )
                .unwrap()
            }
        });
    });

    let module = compile(WASM).expect("Compilation should succeed.");
    let (import_obj, _, _, _, _) = make_imports(
        Which::Init {
            init_ctx: &InitContext {
                init_origin: AccountAddress([0u8; 32]),
                metadata:    ChainMetadata {
                    slot_number:      0,
                    block_height:     0,
                    finalized_height: 0,
                    slot_time:        0,
                },
            },
        },
        Vec::new(),
        1000_000_000,
    );
    c.bench_function("instantiate_from_module", move |b| {
        b.iter(|| module.instantiate(&import_obj).unwrap());
    });
}

/// Benchmark calling a trivial host function.
pub fn bench_call_host(c: &mut Criterion) {
    let sub_one = |x: u32| criterion::black_box(x - 1);
    let import_obj = imports! {
        "test" => {
            "sub_one" => func!(sub_one)
        }
    };

    let bytes = include_bytes!("../bench-artifacts/call-simple.wasm");

    let instance = instantiate(bytes, &import_obj).unwrap();

    c.bench_function("Wasm function invocation", move |b| {
        b.iter(|| {
            assert_eq!(
                instance.call("id", &[wasmer_runtime::Value::I32(1)]).unwrap()[0],
                wasmer_runtime::Value::I32(1)
            )
        })
    });

    let mut group = c.benchmark_group("Sub-one benchmarks.");

    let instance = instantiate(bytes, &import_obj).unwrap();
    group.bench_function("doing 1 host call", move |b| {
        b.iter(|| {
            assert_eq!(
                instance.call("just_call", &[wasmer_runtime::Value::I32(1)]).unwrap()[0],
                wasmer_runtime::Value::I32(0)
            )
        })
    });

    for i in 1..10 {
        let instance = instantiate(bytes, &import_obj).unwrap();
        group.bench_function(&format!("doing {} host calls", i * 10000), move |b| {
            b.iter(|| {
                assert_eq!(
                    instance.call("just_call", &[wasmer_runtime::Value::I32(i * 10000)]).unwrap()
                        [0],
                    wasmer_runtime::Value::I32(0)
                )
            })
        });
    }
}

criterion_group!(wasm, bench_call_host, bench_instantiate);
criterion_main!(wasm);
