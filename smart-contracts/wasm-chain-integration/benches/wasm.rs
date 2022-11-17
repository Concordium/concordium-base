use anyhow::bail;
use concordium_contracts_common::{
    Address, Amount, ChainMetadata, ContractAddress, Parameter, Timestamp,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use wasm_chain_integration::{
    constants::MAX_ACTIVATION_FRAMES,
    utils::TestHost,
    v0::{
        ConcordiumAllowedImports, InitContext, InitHost, Logs, Outcome, PolicyBytes,
        ProcessedImports, ReceiveContext, ReceiveHost, State,
    },
    InterpreterEnergy,
};
use wasm_transform::{
    artifact::{ArtifactNamedImport, TryFromImport},
    machine::{Host, NoInterrupt, Value},
    types::{FunctionType, ValueType},
    *,
};

static CONTRACT_BYTES_SIMPLE_GAME: &[u8] = include_bytes!("./simple_game.wasm");
static CONTRACT_BYTES_COUNTER: &[u8] = include_bytes!("./counter.wasm");
static CONTRACT_BYTES_MINIMAL: &[u8] = include_bytes!("./code/minimal.wasm");
static CONTRACT_BYTES_INSTRUCTIONS: &[u8] = include_bytes!("./code/instruction.wasm");
static CONTRACT_BYTES_MEMORY_INSTRUCTIONS: &[u8] = include_bytes!("./code/memory-instruction.wasm");
static CONTRACT_BYTES_LOOP: &[u8] = include_bytes!("./code/loop-energy.wasm");
static CONTRACT_BYTES_HOST_FUNCTIONS: &[u8] = include_bytes!("./code/host-functions.wasm");

struct MeteringHost {
    energy:            InterpreterEnergy,
    activation_frames: u32,
}

struct MeteringImport {
    tag: MeteringFunc,
    ty:  FunctionType,
}

enum MeteringFunc {
    ChargeEnergy,
    TrackCall,
    TrackReturn,
    ChargeMemoryAlloc,
}

impl TryFromImport for MeteringImport {
    // NB: This does not check whether the types are correct.
    fn try_from_import(
        _ty: &[types::FunctionType],
        import: types::Import,
    ) -> artifact::CompileResult<Self> {
        let m = &import.mod_name;
        if m.name == "concordium_metering" {
            match import.item_name.name.as_ref() {
                "account_energy" => {
                    let tag = MeteringFunc::ChargeEnergy;
                    let ty = FunctionType {
                        parameters: vec![ValueType::I64],
                        result:     None,
                    };
                    Ok(MeteringImport {
                        tag,
                        ty,
                    })
                }
                "track_call" => {
                    let tag = MeteringFunc::TrackCall;
                    let ty = FunctionType {
                        parameters: vec![],
                        result:     None,
                    };
                    Ok(MeteringImport {
                        tag,
                        ty,
                    })
                }
                "track_return" => {
                    let tag = MeteringFunc::TrackReturn;
                    let ty = FunctionType {
                        parameters: vec![],
                        result:     None,
                    };
                    Ok(MeteringImport {
                        tag,
                        ty,
                    })
                }
                "account_memory" => {
                    let tag = MeteringFunc::ChargeMemoryAlloc;
                    let ty = FunctionType {
                        parameters: vec![ValueType::I32],
                        result:     Some(ValueType::I32),
                    };
                    Ok(MeteringImport {
                        tag,
                        ty,
                    })
                }
                name => bail!("Unsupported import {}.", name),
            }
        } else {
            bail!("Unsupported import.")
        }
    }

    fn ty(&self) -> &types::FunctionType { &self.ty }
}

impl Host<MeteringImport> for MeteringHost {
    type Interrupt = NoInterrupt;

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn tick_initial_memory(&mut self, num_pages: u32) -> machine::RunResult<()> {
        self.energy.charge_memory_alloc(num_pages)
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    fn call(
        &mut self,
        f: &MeteringImport,
        _memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<Option<NoInterrupt>> {
        match f.tag {
            MeteringFunc::ChargeEnergy => {
                self.energy.tick_energy(unsafe { stack.pop_u64() }).map(|_| None)
            }
            MeteringFunc::TrackCall => {
                if let Some(fr) = self.activation_frames.checked_sub(1) {
                    self.activation_frames = fr;
                    Ok(None)
                } else {
                    bail!("Too many nested functions.")
                }
            }
            MeteringFunc::TrackReturn => {
                self.activation_frames += 1;
                Ok(None)
            }
            MeteringFunc::ChargeMemoryAlloc => {
                self.energy.charge_memory_alloc(unsafe { stack.peek_u32() }).map(|_| None)
            }
        }
    }
}

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

    // execute n instructions and measure the time
    {
        let mut group = c.benchmark_group("Instruction execution");

        group.measurement_time(Duration::from_secs(10));

        let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_INSTRUCTIONS)).unwrap();
        let module = validate::validate_module(&TestHost::uninitialized(), &skeleton).unwrap();
        let artifact = module.compile::<ArtifactNamedImport>().unwrap();
        for n in [0, 1, 10000, 100000, 200000].iter() {
            group.bench_with_input(format!("execute n = {}", n), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact
                            .run(&mut TestHost::uninitialized(), "foo_extern", &[Value::I64(*m)])
                            .is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        let skeleton =
            parse::parse_skeleton(black_box(CONTRACT_BYTES_MEMORY_INSTRUCTIONS)).unwrap();
        let module = validate::validate_module(&TestHost::uninitialized(), &skeleton).unwrap();
        let artifact = module.compile::<ArtifactNamedImport>().unwrap();
        for n in [1, 10, 50, 100, 250, 500, 1000, 1024].iter() {
            group.bench_with_input(format!("allocate n = {} pages", n), n, |b, m| {
                b.iter(|| {
                    assert!(
                        artifact
                            .run(&mut TestHost::uninitialized(), "foo_extern", &[Value::I32(*m)])
                            .is_ok(),
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
                        artifact
                            .run(&mut TestHost::uninitialized(), "write_u32", &[Value::I32(*m)])
                            .is_ok(),
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
                        artifact
                            .run(&mut TestHost::uninitialized(), "write_u64", &[Value::I32(*m)])
                            .is_ok(),
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
                        artifact
                            .run(&mut TestHost::uninitialized(), "write_u32_u8", &[Value::I32(*m)])
                            .is_ok(),
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
                        artifact
                            .run(&mut TestHost::uninitialized(), "write_u64_u8", &[Value::I32(*m)])
                            .is_ok(),
                        "Precondition violation."
                    )
                })
            });
        }

        group.finish();
    }

    // the exhaust energy benchmark group
    {
        let mut group = c.benchmark_group("Exhaust energy");

        let nrg = 1000;

        // the throughput is meant to correspond to 1NRG. The reported throughput should
        // be around 1M elements per second.
        group
            .measurement_time(Duration::from_secs(10))
            .throughput(criterion::Throughput::Elements(nrg));

        let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_LOOP)).unwrap();
        let mut module = validate::validate_module(&TestHost::uninitialized(), &skeleton).unwrap();
        module.inject_metering().unwrap();
        let artifact = module.compile::<MeteringImport>().unwrap();

        // Execute the function `name` with arguments `args` until running out of
        // energy. Raise an exception if execution terminates in some other way.
        let mut exec = |name, args| {
            let artifact = &artifact;
            group.bench_function(name, move |b: &mut criterion::Bencher| {
                b.iter(|| {
                    let mut host = MeteringHost {
                        energy:            InterpreterEnergy {
                            energy: nrg * 1000, // should correspond to about 1ms of execution.
                        },
                        activation_frames: MAX_ACTIVATION_FRAMES,
                    };
                    let r = artifact
                        .run(&mut host, name, args)
                        .expect_err("Precondition violation, did not terminate with an error.");
                    assert!(
                        r.downcast_ref::<wasm_chain_integration::OutOfEnergy>().is_some(),
                        "Execution did not fail due to out of energy: {}",
                        r
                    )
                })
            });
        };

        exec("loop", &[Value::I32(0)]);
        exec("empty_loop", &[]);
        exec("empty_loop_br_if_success", &[]);
        exec("empty_loop_br_if_fail", &[]);
        exec("br.table_20", &[]);
        exec("call_empty_function", &[]);
        exec("call_empty_function_100", &[]);
        exec("call_empty_function_100_locals", &[]);
        exec("call_indirect_empty_function", &[]);
        exec("call_indirect_empty_function_100", &[]);
        exec("block", &[]);
        exec("block_10", &[]);
        exec("loop_10", &[]);
        exec("drop", &[]);
        exec("select_1", &[]);
        exec("select_2", &[]);
        exec("local.get_i32", &[Value::I32(13)]);
        exec("local.get_i64", &[Value::I64(13)]);
        exec("local.set_i32", &[Value::I32(13)]);
        exec("local.set_i64", &[Value::I64(13)]);
        exec("global.get_i32", &[]);
        exec("global.get_i64", &[]);
        exec("i32.load", &[]);
        exec("i64.load", &[]);
        exec("i32.load.offset", &[]);
        exec("i64.load.offset", &[]);
        exec("i32.load8_u", &[]);
        exec("i32.load8_s", &[]);
        exec("i32.load16_u", &[]);
        exec("i32.load16_s", &[]);
        exec("i64.load8_u", &[]);
        exec("i64.load8_s", &[]);
        exec("i64.load16_u", &[]);
        exec("i64.load16_s", &[]);
        exec("i64.load32_u", &[]);
        exec("i64.load32_s", &[]);
        exec("i32.store", &[]);
        exec("i64.store", &[]);
        exec("i32.store8", &[]);
        exec("i64.store8", &[]);
        exec("i32.store16", &[]);
        exec("i64.store16", &[]);
        exec("i64.store32", &[]);
        exec("memory.size", &[]);
        exec("memory.grow", &[]);
        exec("memory.grow_1_page", &[]);
        exec("i32.const", &[]);
        exec("i64.const", &[]);
        exec("i32.eqz", &[]);
        exec("i32.eq", &[]);
        exec("i32.lt_s", &[]);
        exec("i32.lt_u", &[]);
        exec("i32.gt_s", &[]);
        exec("i32.gt_u", &[]);
        exec("i32.le_s", &[]);
        exec("i32.le_u", &[]);
        exec("i32.ge_s", &[]);
        exec("i32.ge_u", &[]);
        exec("i64.eqz", &[]);
        exec("i64.eq", &[]);
        exec("i64.lt_s", &[]);
        exec("i64.lt_u", &[]);
        exec("i64.gt_s", &[]);
        exec("i64.gt_u", &[]);
        exec("i64.le_s", &[]);
        exec("i64.le_u", &[]);
        exec("i64.ge_s", &[]);
        exec("i64.ge_u", &[]);
        exec("i32.clz", &[]);
        exec("i32.ctz", &[]);
        exec("i32.popcnt", &[]);
        exec("i32.add", &[]);
        exec("i32.sub", &[]);
        exec("i32.mul", &[]);
        exec("i32.div_s", &[]);
        exec("i32.div_u", &[]);
        exec("i32.rem_s", &[]);
        exec("i32.rem_u", &[]);
        exec("i64.clz", &[]);
        exec("i64.ctz", &[]);
        exec("i64.popcnt", &[]);
        exec("i64.add", &[]);
        exec("i64.sub", &[]);
        exec("i64.mul", &[]);
        exec("i64.div_s", &[]);
        exec("i64.div_u", &[]);
        exec("i64.rem_s", &[]);
        exec("i64.rem_u", &[]);
        exec("i32.wrap_i64", &[]);
        group.finish();
    }

    {
        // Benchmarks for host functions.
        // The preconditions (expected state and param) for each function are specified
        // in host-functions.wat
        let mut group = c.benchmark_group("host functions");

        let nrg = 1000;

        // the throughput is meant to correspond to 1NRG. The reported throughput should
        // be around 1M elements per second.
        group
            .measurement_time(Duration::from_secs(10))
            .throughput(criterion::Throughput::Elements(nrg));

        let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_HOST_FUNCTIONS)).unwrap();
        let module = {
            let mut module =
                validate::validate_module(&ConcordiumAllowedImports, &skeleton).unwrap();
            module.inject_metering().expect("Metering injection should succeed.");
            module
        };

        let artifact = module.compile::<ProcessedImports>().unwrap();

        let owner = concordium_contracts_common::AccountAddress([0u8; 32]);

        let init_ctx: InitContext<&[u8]> = InitContext {
            metadata:        ChainMetadata {
                slot_time: Timestamp::from_timestamp_millis(0),
            },
            init_origin:     owner,
            sender_policies: &[],
        };

        let receive_ctx: ReceiveContext<&[u8]> = ReceiveContext {
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
        };

        let setup_init_host = || -> InitHost<Parameter<'_>, &InitContext<PolicyBytes<'_>>> {
            InitHost {
                energy: InterpreterEnergy {
                    energy: nrg * 1000,
                },
                activation_frames: MAX_ACTIVATION_FRAMES,
                logs: Logs::new(),
                state: State::new(None),
                param: Parameter::from(&[] as &[u8]),
                init_ctx: &init_ctx,
                limit_logs_and_return_values: false,
            }
        };

        let setup_receive_host =
            |state, param| -> ReceiveHost<Parameter<'_>, &ReceiveContext<PolicyBytes<'_>>> {
                ReceiveHost {
                    energy: InterpreterEnergy {
                        energy: nrg * 1000,
                    },
                    activation_frames: MAX_ACTIVATION_FRAMES,
                    logs: Logs::new(),
                    state,
                    param,
                    outcomes: Outcome::new(),
                    receive_ctx: &receive_ctx,
                    max_parameter_size: u16::MAX.into(),
                    limit_logs_and_return_values: false,
                }
            };

        let run_init = |name, args| {
            // since we move the rest of the variables we must first take a reference to
            // only move the reference to the artifact making this closure copyable.
            let artifact = &artifact;
            move |b: &mut criterion::Bencher| {
                b.iter( || {
                let mut host = setup_init_host();
                let r = artifact
                    .run(&mut host, name, args)
                    .expect_err("Execution should fail due to out of energy.");
                assert!(
                    r.downcast_ref::<wasm_chain_integration::OutOfEnergy>().is_some(), /* Should fail due to out of energy. */
                    "Execution did not fail due to out of energy: {}.",
                    r
                );
                }
                )
            }
        };

        let run_receive = |state, params: &'static [u8], name, args| {
            // since we move the rest of the variables we must first take a reference to
            // only move the reference to the artifact making this closure copyable.
            let artifact = &artifact;
            move |b: &mut criterion::Bencher| {
                b.iter(|| {
                    let mut host = setup_receive_host(State::new(state), params.into());
                    let r = artifact
                        .run(&mut host, name, args)
                        .expect_err("Execution should fail due to out of energy.");
                    assert!(
                        r.downcast_ref::<wasm_chain_integration::OutOfEnergy>().is_some(), /* Should fail due to out of energy. */
                        "Execution did not fail due to out of energy: {}.",
                        r
                    );
            })
            }
        };

        group.bench_function(
            "log_event",
            run_receive(None, &[], "hostfn.log_event", &[Value::I64(0)]),
        );

        group.bench_function(
            "get_parameter_size",
            run_receive(None, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "hostfn.get_parameter_size", &[
                Value::I64(0),
            ]),
        );

        group.bench_function(
            "get_parameter_section",
            run_receive(None, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "hostfn.get_parameter_section", &[
                Value::I64(0),
            ]),
        );

        group.bench_function(
            "state_size",
            run_receive(Some(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), &[], "hostfn.state_size", &[
                Value::I64(0),
            ]),
        );

        group.bench_function(
            "load_state",
            run_receive(Some(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), &[], "hostfn.load_state", &[
                Value::I64(0),
            ]),
        );

        group.bench_function(
            "write_state",
            run_receive(Some(&[0u8; 1 << 16]), &[], "hostfn.write_state", &[Value::I64(0)]),
        );

        group.bench_function(
            "resize_state",
            run_receive(None, &[], "hostfn.resize_state", &[Value::I64(0)]),
        );

        group.bench_function(
            "get_slot_time",
            run_receive(None, &[], "hostfn.get_slot_time", &[Value::I64(0)]),
        );

        group.bench_function("get_init_origin", run_init("init_get_init_origin", &[Value::I64(0)]));

        group.bench_function(
            "get_receive_invoker",
            run_receive(None, &[], "hostfn.get_receive_invoker", &[Value::I64(0)]),
        );

        group.bench_function(
            "get_receive_sender",
            run_receive(None, &[], "hostfn.get_receive_sender", &[Value::I64(0)]),
        );

        group.bench_function(
            "get_receive_self_address",
            run_receive(None, &[], "hostfn.get_receive_self_address", &[Value::I64(0)]),
        );

        group.bench_function(
            "get_receive_owner",
            run_receive(None, &[], "hostfn.get_receive_owner", &[Value::I64(0)]),
        );

        group.bench_function(
            "get_receive_self_balance",
            run_receive(None, &[], "hostfn.get_receive_self_balance", &[Value::I64(0)]),
        );

        group.bench_function("accept", run_receive(None, &[], "hostfn.accept", &[Value::I64(0)]));

        group.bench_function(
            "simple_transfer",
            run_receive(None, &[], "hostfn.simple_transfer", &[Value::I64(0)]),
        );

        group.bench_function("send", run_receive(None, &[], "hostfn.send", &[Value::I64(0)]));

        group.bench_function(
            "combine_and",
            run_receive(None, &[], "hostfn.combine_and", &[Value::I64(0)]),
        );

        group.bench_function(
            "combine_or",
            run_receive(None, &[], "hostfn.combine_or", &[Value::I64(0)]),
        );
        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
