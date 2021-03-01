use anyhow::bail;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use wasm_chain_integration::{
    constants::MAX_ACTIVATION_FRAMES, ConcordiumAllowedImports, Energy, ProcessedImports, TestHost,
};
use wasm_transform::{
    artifact::{ArtifactNamedImport, TryFromImport},
    machine::{Host, Value},
    types::{FunctionType, ValueType},
    *,
};

static CONTRACT_BYTES_SIMPLE_GAME: &[u8] = include_bytes!("./simple_game.wasm");
static CONTRACT_BYTES_COUNTER: &[u8] = include_bytes!("./counter.wasm");
static CONTRACT_BYTES_MINIMAL: &[u8] = include_bytes!("./code/minimal.wasm");
static CONTRACT_BYTES_INSTRUCTIONS: &[u8] = include_bytes!("./code/instruction.wasm");
static CONTRACT_BYTES_MEMORY_INSTRUCTIONS: &[u8] = include_bytes!("./code/memory-instruction.wasm");
static CONTRACT_BYTES_LOOP: &[u8] = include_bytes!("./code/loop-energy.wasm");

struct MeteringHost {
    energy:            Energy,
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
    #[inline(always)]
    fn tick_initial_memory(&mut self, num_pages: u32) -> machine::RunResult<()> {
        self.energy.charge_memory_alloc(num_pages)
    }

    #[inline]
    fn call(
        &mut self,
        f: &MeteringImport,
        _memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<()> {
        match f.tag {
            MeteringFunc::ChargeEnergy => self.energy.tick_energy(unsafe { stack.pop_u64() }),
            MeteringFunc::TrackCall => {
                if let Some(fr) = self.activation_frames.checked_sub(1) {
                    self.activation_frames = fr;
                    Ok(())
                } else {
                    bail!("Too many nested functions.")
                }
            }
            MeteringFunc::TrackReturn => {
                self.activation_frames += 1;
                Ok(())
            }
            MeteringFunc::ChargeMemoryAlloc => {
                self.energy.charge_memory_alloc(unsafe { stack.peek_u32() })
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

    {
        let mut group = c.benchmark_group("Exhaust energy");

        group.measurement_time(Duration::from_secs(20));

        let skeleton = parse::parse_skeleton(black_box(CONTRACT_BYTES_LOOP)).unwrap();
        let mut module = validate::validate_module(&TestHost, &skeleton).unwrap();
        module.inject_metering().unwrap();
        let artifact = module.compile::<MeteringImport>().unwrap();
        for energy in [1000, 10000, 100000, 1000000].iter() {
            group.bench_with_input(
                format!("execute with energy n = {}", energy),
                energy,
                |b, &energy| {
                    b.iter(|| {
                        let mut host = MeteringHost {
                            energy:            Energy {
                                energy,
                            },
                            activation_frames: MAX_ACTIVATION_FRAMES,
                        };
                        assert!(
                            // Should fail due to out of energy.
                            artifact.run(&mut host, "loop", &[Value::I32(0)]).is_err(),
                            "Precondition violation."
                        )
                    })
                },
            );
        }

        for energy in [1000, 10000, 100000, 1000000].iter() {
            group.bench_with_input(
                format!("timeout with energy n = {}", energy),
                energy,
                |b, &energy| {
                    b.iter(|| {
                        let mut host = MeteringHost {
                            energy:            Energy {
                                energy,
                            },
                            activation_frames: MAX_ACTIVATION_FRAMES,
                        };
                        let r = artifact.run(&mut host, "empty_loop", &[]).expect_err("Precondition violation. Execution should fail.");
                        assert!(
                            r.downcast_ref::<wasm_chain_integration::OutOfEnergy>().is_some(), // Should fail due to out of energy.
                            "Execution did not fail due to out of energy: {}.", r
                        )
                    })
                },
            );
        }

        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
