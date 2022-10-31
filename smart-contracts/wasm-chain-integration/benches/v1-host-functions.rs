//! Benchmarks to help establish costs for V1 host functions. The benchmarks
//! are written with the intent that they measure representative or worst-case
//! uses of functions, depending on the needs. Execution time, as well as energy
//! throughput are measured. These are then used as input to assigning costs to
//! relevant operations. Note that often there are other concerns than just
//! execution time when assigning costs, so benchmarks here should generally
//! only ensure that a sufficiently low upper bound is there.
use concordium_contracts_common::{
    Address, Amount, ChainMetadata, ContractAddress, OwnedEntrypointName, Timestamp,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use sha2::Digest;
use std::time::Duration;
use wasm_chain_integration::{
    constants::MAX_ACTIVATION_FRAMES,
    v0,
    v1::{
        trie::{
            self, low_level::MutableTrie, EmptyCollector, Loader, MutableState, PersistentState,
        },
        ConcordiumAllowedImports, InstanceState, ProcessedImports, ReceiveContext, ReceiveHost,
        ReceiveParams, StateLessReceiveHost,
    },
    InterpreterEnergy,
};
use wasm_transform::{machine, parse, validate};

static CONTRACT_BYTES_HOST_FUNCTIONS: &[u8] = include_bytes!("./code/v1/host-functions.wasm");

/// Construct the initial state for the benchmark from given key-value pairs.
fn mk_state<A: AsRef<[u8]>, B: Copy>(inputs: &[(A, B)]) -> (MutableState, Loader<Vec<u8>>)
where
    Vec<u8>: From<B>, {
    let mut node = MutableTrie::empty();
    let mut loader = Loader {
        inner: Vec::new(),
    };
    for (k, v) in inputs {
        node.insert(&mut loader, k.as_ref(), trie::Value::from(*v))
            .expect("No locks, so cannot fail.");
    }
    if let Some(trie) = node.freeze(&mut loader, &mut EmptyCollector) {
        (PersistentState::from(trie).thaw(), loader)
    } else {
        (PersistentState::Empty.thaw(), loader)
    }
}

/// Benchmarks for host functions.
/// The preconditions (expected state and param) for each function are specified
/// in ./code/v1/host-functions.wat
pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("v1 host functions");

    let nrg = 1000;

    let start_energy = InterpreterEnergy {
        energy: nrg * 1000,
    };

    // the throughput is meant to correspond to 1NRG. The reported throughput should
    // be around 1M elements per second.
    group
        .measurement_time(Duration::from_secs(10))
        .throughput(criterion::Throughput::Elements(nrg));

    let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_HOST_FUNCTIONS)).unwrap();
    let module = {
        let mut module = validate::validate_module(
            &ConcordiumAllowedImports {
                support_upgrade: true,
            },
            &skeleton,
        )
        .unwrap();
        module.inject_metering().expect("Metering injection should succeed.");
        module
    };

    let artifact = module.compile::<ProcessedImports>().unwrap();

    let owner = concordium_contracts_common::AccountAddress([0u8; 32]);

    let receive_ctx: ReceiveContext<&[u8]> = ReceiveContext {
        common:     v0::ReceiveContext {
            metadata: ChainMetadata {
                slot_time: Timestamp::from_timestamp_millis(0),
            },
            invoker: owner,
            self_address: ContractAddress {
                index:    0,
                subindex: 0,
            },
            self_balance: Amount::from_ccd(1000),
            sender: Address::Account(owner),
            owner,
            sender_policies: &[],
        },
        entrypoint: OwnedEntrypointName::new_unchecked("entrypoint".into()),
    };

    let mut add_benchmark = |name: &str, args: [_; 1], n, empty_state: bool| {
        let params = vec![17u8; n];
        let inputs = if empty_state {
            Vec::new()
        } else {
            let mut inputs = Vec::with_capacity(n + 1);
            // construct the trie with the most nodes on the path to the
            // key we will look up.
            for i in 0..=n {
                inputs.push((params[0..i].to_vec(), i.to_be_bytes()));
            }
            inputs
        };
        let artifact = &artifact;
        let params = &params;
        let mk_data = || {
            let (a, b) = mk_state(&inputs);
            (a, b, vec![params.clone()])
        };
        let receive_ctx = &receive_ctx;
        let args = &args[..];
        group.bench_function(format!("{} n = {}", name, n), move |b: &mut criterion::Bencher| {
            b.iter_batched(
                mk_data,
                |(mut mutable_state, _, parameters)| {
                    let mut backing_store = Loader {
                        inner: Vec::new(),
                    };
                    let inner = mutable_state.get_inner(&mut backing_store);
                    let state = InstanceState::new(backing_store, inner);
                    let mut host = ReceiveHost::<_, Vec<u8>, _> {
                        energy: start_energy,
                        stateless: StateLessReceiveHost {
                            activation_frames: MAX_ACTIVATION_FRAMES,
                            logs: v0::Logs::new(),
                            receive_ctx,
                            return_value: Vec::new(),
                            parameters,
                            params: ReceiveParams::new_p5(),
                        },
                        state,
                    };
                    let r = artifact
                        .run(&mut host, name, args)
                        .expect_err("Execution should fail due to out of energy.");
                    // Should fail due to out of energy.
                    assert!(
                        r.downcast_ref::<wasm_chain_integration::OutOfEnergy>().is_some(),
                        "Execution did not fail due to out of energy: {}.",
                        r
                    );
                    let params = std::mem::take(&mut host.stateless.parameters);
                    // it is not ideal to drop the host here since it might contain iterators and
                    // entries which do take a bit of time to drop.
                    drop(host);
                    // return the state so that its drop is not counted in the benchmark.
                    (mutable_state, params)
                },
                if n <= 10 {
                    BatchSize::SmallInput
                } else {
                    BatchSize::LargeInput
                },
            )
        });
    };

    for n in [0, 2, 10, 20, 40, 50, 100, 1000] {
        let name = "hostfn.state_create_entry";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000] {
        let name = "hostfn.state_lookup_entry";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000] {
        let name = "hostfn.state_entry_size";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000] {
        let name = "hostfn.state_entry_read";
        let args = [machine::Value::I64(n as i64)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_entry_write";
        let args = [machine::Value::I64(n as i64)];
        add_benchmark(name, args, n, false)
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_delete_entry";
        let args = [machine::Value::I64(n as i64)];
        add_benchmark(name, args, n, false)
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_delete_entry_nonexistent";
        let args = [machine::Value::I64(n as i64)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_iterate_prefix";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_delete_prefix";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_iterator_key_size";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false)
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_iterator_key_read";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false);
    }

    for n in [0, 2, 10, 20, 50, 100, 1000, 10000] {
        let name = "hostfn.state_iterator_delete";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false)
    }

    for n in [0, 2, 10, 20, 50, 100, 10000] {
        let name = "hostfn.state_iterator_next";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, false)
    }

    for n in [0, 2, 10, 20, 50, 100, 10000] {
        let name = "hostfn.write_output";
        let args = [machine::Value::I64(0)];
        add_benchmark(name, args, n, true)
    }

    let mut add_invoke_benchmark = |name: &'static str, params: Vec<u8>, name_ext| {
        let args = [machine::Value::I64(0)];
        let inputs: Vec<(Vec<u8>, [u8; 1])> = Vec::new();
        let artifact = &artifact;
        let params = &params;
        let mk_data = || {
            let (a, b) = mk_state(&inputs);
            (a, b, vec![params.clone()])
        };
        let receive_ctx = &receive_ctx;
        let args = &args[..];
        let bench_name = if let Some(n) = name_ext {
            format!("{} n = {}", name, n)
        } else {
            name.to_string()
        };
        group.bench_function(bench_name, move |b: &mut criterion::Bencher| {
            b.iter_batched(
                mk_data,
                |(mut mutable_state, _, parameters)| {
                    let mut backing_store = Loader {
                        inner: Vec::new(),
                    };
                    let inner = mutable_state.get_inner(&mut backing_store);
                    let state = InstanceState::new(backing_store, inner);
                    let mut host = ReceiveHost::<_, Vec<u8>, _> {
                        energy: start_energy,
                        stateless: StateLessReceiveHost {
                            activation_frames: MAX_ACTIVATION_FRAMES,
                            logs: v0::Logs::new(),
                            receive_ctx,
                            return_value: Vec::new(),
                            parameters,
                            params: ReceiveParams::new_p5()
                        },
                        state,
                    };
                    match artifact.run(&mut host, name, args) {
                        Ok(r) => match r {
                            machine::ExecutionOutcome::Success {
                                ..
                            } => panic!("Execution terminated, but it was not expected to."),
                            machine::ExecutionOutcome::Interrupted {
                                reason: _,
                                config,
                            } => {
                                let mut current_config = config;
                                loop {
                                    current_config.push_value(0u64); // push the response to the stack, the value is not inspected.
                                    match artifact.run_config(&mut host, current_config) {
                                        Ok(r) => {
                                            match r {
                                                machine::ExecutionOutcome::Success { .. } => panic!("Execution terminated, but it was not expected to."),
                                                machine::ExecutionOutcome::Interrupted { config,.. } => {
                                                    current_config = config;
                                                }
                                            }
                                        }
                                        Err(r) => {
                                            // Should fail due to out of energy.
                                            assert!(
                                                r.downcast_ref::<wasm_chain_integration::OutOfEnergy>().is_some(),
                                                "Execution did not fail due to out of energy: {}.",
                                                r
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        },
                        Err(err) => {
                            panic!("Initial invocation should not fail: {}", err);
                        }
                    }
                    // it is not ideal to drop the host here since it might contain iterators and
                    // entries which do take a bit of time to drop.
                    drop(host);
                    // return the state so that its drop is not counted in the benchmark.
                    (mutable_state, params)
                },
                BatchSize::SmallInput
            )
        });
    };

    {
        let name = "hostfn.invoke_transfer";
        let params = vec![0u8; 32 + 8]; // address + amount
        add_invoke_benchmark(name, params, None);
    }

    {
        // n is the length of the parameter
        for n in [0, 10, 20, 50, 100, 1000, 10000] {
            let name = "hostfn.invoke_contract";
            let mut params = vec![0u8; 16 + 2 + n + 2 + 8]; // address + amount
            params[16..16 + 2].copy_from_slice(&(n as u16).to_le_bytes());
            add_invoke_benchmark(name, params, Some(n));
        }
    }

    let mut add_crypto_primitive_benchmark = |name: &'static str, params: Vec<u8>, name_ext| {
        let args = [machine::Value::I64(0)];
        let inputs: Vec<(Vec<u8>, [u8; 1])> = Vec::new();
        let artifact = &artifact;
        let params = &params;
        let mk_data = || {
            let (a, b) = mk_state(&inputs);
            (a, b, vec![params.clone()])
        };
        let receive_ctx = &receive_ctx;
        let args = &args[..];
        let bench_name = if let Some(n) = name_ext {
            format!("{} n = {}", name, n)
        } else {
            name.to_string()
        };
        group.bench_function(bench_name, move |b: &mut criterion::Bencher| {
            b.iter_batched(
                mk_data,
                |(mut mutable_state, _, parameters)| {
                    let mut backing_store = Loader {
                        inner: Vec::new(),
                    };
                    let inner = mutable_state.get_inner(&mut backing_store);
                    let state = InstanceState::new(backing_store, inner);
                    let mut host = ReceiveHost::<_, Vec<u8>, _> {
                        energy: start_energy,
                        stateless: StateLessReceiveHost {
                            activation_frames: MAX_ACTIVATION_FRAMES,
                            logs: v0::Logs::new(),
                            receive_ctx,
                            return_value: Vec::new(),
                            parameters,
                            params: ReceiveParams::new_p5(),
                        },
                        state,
                    };
                    let r = artifact
                        .run(&mut host, name, args)
                        .expect_err("Execution should fail due to out of energy.");
                    // Should fail due to out of energy.
                    assert!(
                        r.downcast_ref::<wasm_chain_integration::OutOfEnergy>().is_some(),
                        "Execution did not fail due to out of energy: {}.",
                        r
                    );
                    let params = std::mem::take(&mut host.stateless.parameters);
                    // it is not ideal to drop the host here since it could significantly affect the
                    // cost for small samples.
                    drop(host);
                    // return the state so that its drop is not counted in the benchmark.
                    (mutable_state, params)
                },
                BatchSize::SmallInput,
            )
        });
    };

    {
        // n is the length of the data to be hashed
        for n in [0u32, 10, 20, 50, 100, 1000, 10_000, 100_000] {
            let name = "hostfn.verify_ed25519_signature";
            let sk = ed25519_zebra::SigningKey::from([1u8; 32]);
            let sig = sk.sign(&vec![0u8; n as usize]); // sign a zero message of a given length.
            let pk = ed25519_zebra::VerificationKey::from(&sk);
            let mut params = Vec::with_capacity(100);
            params.extend_from_slice(pk.as_ref());
            params.extend_from_slice(&<[u8; 64]>::from(sig)[..]);
            params.extend_from_slice(&n.to_le_bytes());
            add_crypto_primitive_benchmark(name, params, Some(n));
        }
    }

    {
        // ecdsa verification has a fixed message length
        let name = "hostfn.verify_ecdsa_secp256k1_signature";
        let signer = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[
            0xc9, 0xef, 0x15, 0x44, 0x4b, 0x1e, 0x88, 0x5f, 0x0e, 0xd0, 0x36, 0xaa, 0xc8, 0x64,
            0x6f, 0xb0, 0xc6, 0x11, 0x88, 0x6e, 0x8c, 0x40, 0x91, 0xa1, 0xb7, 0xb2, 0xb5, 0xa0,
            0x95, 0xd2, 0xd6, 0xba,
        ])
        .expect("Key generated with openssl, so should be valid.");
        let message = secp256k1::Message::from_slice(&sha2::Sha256::digest(&[])[..])
            .expect("Hashes are valid messages.");
        let sig = signer.sign_ecdsa(&message, &sk);
        let pk = secp256k1::PublicKey::from_slice(&[
            0x04, 0xbb, 0xc0, 0xa1, 0xad, 0x6f, 0x0d, 0x2c, 0x1f, 0x32, 0x50, 0xd9, 0x08, 0x78,
            0x15, 0x37, 0xd6, 0x8c, 0xf4, 0xa6, 0x96, 0x41, 0x74, 0xb9, 0x70, 0x36, 0x2c, 0x66,
            0x47, 0x52, 0x11, 0xc6, 0xf8, 0x70, 0xd4, 0xc1, 0x99, 0xc7, 0x93, 0xbf, 0x3d, 0x6c,
            0x21, 0x55, 0x2d, 0xad, 0xee, 0xc5, 0x1b, 0x6a, 0x3f, 0xa6, 0x0a, 0x7c, 0x1a, 0x1f,
            0x63, 0xd5, 0x8f, 0xf5, 0x51, 0x7b, 0x74, 0xf8, 0x12,
        ])
        .expect(
            "Should be a valid public key matching the secret key above. Generated with openssl.",
        );
        let mut params = Vec::with_capacity(100);
        params.extend_from_slice(&pk.serialize());
        params.extend_from_slice(&sig.serialize_compact());
        params.extend_from_slice(message.as_ref());
        add_crypto_primitive_benchmark(name, params, None);
    }

    {
        // n is the length of the data to be hashed
        for n in [0u32, 10, 20, 50, 100, 1000, 10_000, 100_000] {
            let name = "hostfn.hash_sha2_256";
            let params = n.to_le_bytes().to_vec(); // length to hash
            add_crypto_primitive_benchmark(name, params, Some(n));
        }
    }

    {
        // n is the length of the data to be hashed
        for n in [0u32, 10, 20, 50, 100, 1000, 10_000, 100_000] {
            let name = "hostfn.hash_sha3_256";
            let params = n.to_le_bytes().to_vec(); // length to hash
            add_crypto_primitive_benchmark(name, params, Some(n));
        }
    }

    {
        // n is the length of the data to be hashed
        for n in [0u32, 10, 20, 50, 100, 1000, 10_000, 100_000] {
            let name = "hostfn.hash_keccak_256";
            let params = n.to_le_bytes().to_vec(); // length to hash
            add_crypto_primitive_benchmark(name, params, Some(n));
        }
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
