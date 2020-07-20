#[macro_use]
extern crate criterion;

use criterion::Criterion;
use wasmer_interp::*;
use wasmer_runtime::{compile, instantiate};
use wasmer_runtime_core::validate;

static WASM: &[u8] = include_bytes!(
    "/home/abizjak/Documents/Concordium/prototype/smart-contracts/rust-contracts/\
     example-contracts/counter/target/wasm32-unknown-unknown/release/counter.wasm"
);

pub fn bench_instantiate(c: &mut Criterion) {
    let (import_obj, _, _, _) = make_imports(Which::Init {
        init_ctx: InitContext {
            init_origin: [0u8; 32],
        },
    });

    c.bench_function("instantiate", move |b| b.iter(|| instantiate(WASM, &import_obj)));

    c.bench_function("compile", move |b| b.iter(|| compile(WASM)));

    c.bench_function("validate", move |b| b.iter(|| assert!(validate(WASM))));

    let module = compile(WASM).expect("Compilation should succeed.");

    c.bench_function("make_artifacct", move |b| {
        b.iter(|| {
            module.cache().expect("Could not make a cache.");
        })
    });

    let module = compile(WASM).expect("Compilation should succeed.");
    let artifact = module.cache().expect("Could not make a cache.");
    let bytes = artifact.serialize().expect("Should be able to serialize bytes");

    c.bench_function("load_from_cache", move |b| {
        b.iter(|| {
            let artifact = module.cache().expect("Could not make a cache.");
            unsafe {
                wasmer_runtime_core::load_cache_with(
                    artifact,
                    &*wasmer_runtime::compiler_for_backend(wasmer_runtime::Backend::Cranelift)
                        .unwrap(),
                )
                .unwrap()
            }
        });
    });

    c.bench_function("load_from_bytes", move |b| {
        b.iter(|| {
            let artifact = wasmer_runtime_core::cache::Artifact::deserialize(&bytes)
                .expect("Should be able to deserialize");
            unsafe {
                wasmer_runtime_core::load_cache_with(
                    artifact,
                    &*wasmer_runtime::compiler_for_backend(wasmer_runtime::Backend::Cranelift)
                        .unwrap(),
                )
                .unwrap()
            }
        });
    });
}

criterion_group!(wasm, bench_instantiate);
criterion_main!(wasm);
