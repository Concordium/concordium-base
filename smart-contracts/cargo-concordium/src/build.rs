use ansi_term::{Color, Style};
use anyhow::Context;
use cargo_toml::Manifest;
use concordium_contracts_common::*;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};
use wasm_chain_integration::{
    utils::{self, WasmVersion},
    v0, v1, ExecResult,
};
use wasm_transform::{
    output::{write_custom_section, Output},
    parse::parse_skeleton,
    types::{CustomSection, ExportDescription, Module},
    utils::strip,
    validate::validate_module,
};

fn to_snake_case(string: String) -> String { string.to_lowercase().replace('-', "_") }

#[derive(Debug, Clone, Copy)]
pub enum SchemaBuildOptions {
    DoNotBuild,
    JustBuild,
    BuildAndEmbed,
}

impl SchemaBuildOptions {
    /// Return whether the schema should be built.
    pub fn build(self) -> bool {
        matches!(self, SchemaBuildOptions::JustBuild | SchemaBuildOptions::BuildAndEmbed)
    }

    /// Return whether the schema should be embedded.
    pub fn embed(self) -> bool { matches!(self, SchemaBuildOptions::BuildAndEmbed) }
}

/// Build a contract and its schema.
/// If build_schema is set then the return value will contain the schema of the
/// version specified.
pub fn build_contract(
    version: utils::WasmVersion,
    build_schema: SchemaBuildOptions,
    out: Option<PathBuf>,
    cargo_args: &[String],
) -> anyhow::Result<(usize, Option<schema::VersionedModuleSchema>)> {
    #[allow(unused_assignments)]
    // This assignment is not actually unused. It is used via the custom_section which retains a
    // reference to this vector, which is why it has to be here. This is a bit ugly, but not as
    // ugly as alternatives.
    let mut schema_bytes = Vec::new();
    /* if none do not build. If Some(true) then embed, otherwise
     * just build and return */
    let schema = match version {
        utils::WasmVersion::V0 => {
            if build_schema.build() {
                let schema = build_contract_schema(cargo_args, utils::generate_contract_schema_v0)
                    .context("Could not build module schema.")?;
                if build_schema.embed() {
                    schema_bytes = to_bytes(&schema);
                    let custom_section = CustomSection {
                        name:     "concordium-schema".into(),
                        contents: &schema_bytes,
                    };
                    Some((Some(custom_section), schema))
                } else {
                    Some((None, schema))
                }
            } else {
                None
            }
        }
        utils::WasmVersion::V1 => {
            if build_schema.build() {
                let schema = build_contract_schema(cargo_args, utils::generate_contract_schema_v1)
                    .context("Could not build module schema.")?;
                if build_schema.embed() {
                    schema_bytes = to_bytes(&schema);
                    let custom_section = CustomSection {
                        name:     "concordium-schema".into(),
                        contents: &schema_bytes,
                    };
                    Some((Some(custom_section), schema))
                } else {
                    Some((None, schema))
                }
            } else {
                None
            }
        }
    };

    let manifest = Manifest::from_path("Cargo.toml").context("Could not read Cargo.toml.")?;
    let package = manifest.package.context("Manifest needs to specify [package]")?;

    let result = Command::new("cargo")
        .arg("build")
        .args(&["--target", "wasm32-unknown-unknown"])
        .args(&["--release"])
        .args(&["--target-dir", "target/concordium"])
        .args(cargo_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .context("Could not use cargo build.")?;

    if !result.status.success() {
        anyhow::bail!("Compilation failed.")
    }

    let filename = format!(
        "target/concordium/wasm32-unknown-unknown/release/{}.wasm",
        to_snake_case(package.name)
    );

    let wasm = fs::read(&filename).context("Could not read cargo build Wasm output.")?;

    let mut skeleton =
        parse_skeleton(&wasm).context("Could not parse the skeleton of the module.")?;

    // Remove all custom sections to reduce the size of the module
    strip(&mut skeleton);
    match version {
        utils::WasmVersion::V0 => {
            let module = validate_module(&v0::ConcordiumAllowedImports, &skeleton)
                .context("Could not validate resulting smart contract module as a V0 contract.")?;
            check_exports(&module, WasmVersion::V0)
                .context("Contract and entrypoint validation failed for a V0 contract.")?;
            module
        }
        utils::WasmVersion::V1 => {
            let module = validate_module(&v1::ConcordiumAllowedImports, &skeleton)
                .context("Could not validate resulting smart contract module as a V1 contract.")?;
            check_exports(&module, WasmVersion::V1)
                .context("Contract and entrypoint validation failed for a V1 contract.")?;
            module
        }
    };

    // We output a versioned module that can be directly deployed to the chain,
    // i.e., the exact data that needs to go into the transaction. This starts with
    // the version number in big endian. The remaining 4 bytes are a placeholder for
    // length.
    let mut output_bytes = match version {
        utils::WasmVersion::V0 => vec![0, 0, 0, 0, 0, 0, 0, 0],
        utils::WasmVersion::V1 => vec![0, 0, 0, 1, 0, 0, 0, 0],
    };
    // Embed schema custom section
    skeleton.output(&mut output_bytes)?;
    let return_schema = if let Some((custom_section, schema)) = schema {
        if let Some(custom_section) = custom_section {
            write_custom_section(&mut output_bytes, &custom_section)?;
        }
        Some(schema)
    } else {
        None
    };
    // write the size of the actual module to conform to serialization expected on
    // the chain
    let data_size = (output_bytes.len() - 8) as u32;
    (&mut output_bytes[4..8]).copy_from_slice(&data_size.to_be_bytes());

    let out_filename = out.unwrap_or_else(|| {
        let extension = match version {
            utils::WasmVersion::V0 => "v0",
            utils::WasmVersion::V1 => "v1",
        };
        PathBuf::from(format!("{}.{}", filename, extension))
    });
    let total_module_len = output_bytes.len();
    fs::write(out_filename, output_bytes)?;
    Ok((total_module_len, return_schema))
}

/// Check that exports of module conform to the specification so that they will
/// be accepted by the chain.
fn check_exports(module: &Module, version: WasmVersion) -> anyhow::Result<()> {
    // collect contracts in the module.
    let mut contracts = BTreeSet::new();
    let mut methods = BTreeMap::<_, BTreeSet<OwnedEntrypointName>>::new();
    for export in &module.export.exports {
        if let ExportDescription::Func {
            ..
        } = export.description
        {
            if let Ok(cn) = ContractName::new(export.name.as_ref()) {
                contracts.insert(cn.contract_name());
            } else if let Ok(rn) = ReceiveName::new(export.name.as_ref()) {
                methods
                    .entry(rn.contract_name())
                    .or_insert_with(BTreeSet::new)
                    .insert(rn.entrypoint_name().into());
            } else {
                // for V0 contracts we do not allow any other functions.
                match version {
                    WasmVersion::V0 => anyhow::bail!(
                        "The module has '{}' as an exposed function, which is neither a valid \
                         init or receive method.\nV0 contracts do not allow any exported \
                         functions that are neither init or receive methods.\n",
                        export.name.as_ref()
                    ),
                    WasmVersion::V1 => (),
                }
            }
        }
    }
    for (cn, _ens) in methods {
        if let Some(closest) = find_closest(contracts.iter().copied(), cn) {
            if closest.is_empty() {
                anyhow::bail!(
                    "An entrypoint is declared for a contract '{}', but no contracts exist in the \
                     module.",
                    cn
                );
            } else if closest.len() == 1 {
                anyhow::bail!(
                    "An entrypoint is declared for a contract '{}', but such a contract does not \
                     exist in the module.\nPerhaps you meant '{}'?",
                    cn,
                    closest[0]
                );
            } else {
                let list =
                    closest.into_iter().map(|x| format!("'{}'", x)).collect::<Vec<_>>().join(", ");
                anyhow::bail!(
                    "An entrypoint is declared for a contract '{}', but such a contract does not \
                     exist in the module.\nPerhaps you meant one of [{}].",
                    cn,
                    list
                );
            }
        }
    }
    Ok(())
}

/// Find the string closest to the list of strings. If an exact match is found
/// return `None`, otherwise return `Some` with a list of strings that are
/// closest according to the [optimal string alignment metric](https://en.wikipedia.org/wiki/Damerau%E2%80%93Levenshtein_distance distance).
fn find_closest<'a>(
    list: impl IntoIterator<Item = &'a str>,
    goal: &'a str,
) -> Option<Vec<&'a str>> {
    let mut out = Vec::new();
    let mut least = usize::MAX;
    for cn in list.into_iter() {
        let dist = strsim::osa_distance(cn, goal);
        if dist == 0 {
            return None;
        }
        match dist.cmp(&least) {
            Ordering::Less => {
                out.clear();
                out.push(cn);
                least = dist;
            }
            Ordering::Equal => {
                out.push(cn);
            }
            Ordering::Greater => {
                // do nothing since this candidate is not useful
            }
        }
    }
    Some(out)
}

/// Generates the contract schema by compiling with the 'build-schema' feature
/// Then extracts the schema from the schema build
pub fn build_contract_schema<A>(
    cargo_args: &[String],
    generate_schema: impl FnOnce(&[u8]) -> ExecResult<A>,
) -> anyhow::Result<A> {
    let manifest = Manifest::from_path("Cargo.toml").context("Could not read Cargo.toml.")?;
    let package = manifest.package.context("Manifest needs to specify [package]")?;

    let result = Command::new("cargo")
        .arg("build")
        .args(&["--target", "wasm32-unknown-unknown"])
        .arg("--release")
        .args(&["--features", "concordium-std/build-schema"])
        .args(&["--target-dir", "target/concordium"])
        .args(cargo_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .context("Could not run cargo build.")?;

    if !result.status.success() {
        anyhow::bail!("Compilation failed.");
    }

    let filename = format!(
        "target/concordium/wasm32-unknown-unknown/release/{}.wasm",
        to_snake_case(package.name)
    );

    let wasm =
        std::fs::read(filename).context("Could not read cargo build contract schema output.")?;
    let schema =
        generate_schema(&wasm).context("Could not generate module schema from Wasm module.")?;
    Ok(schema)
}

/// Build tests and run them. If errors occur in building the tests, or there
/// are runtime exceptions that are not expected then this function returns
/// Err(...).
///
/// Otherwise a boolean is returned, signifying whether the tests succeeded or
/// failed.
pub fn build_and_run_wasm_test(extra_args: &[String]) -> anyhow::Result<bool> {
    let manifest = Manifest::from_path("Cargo.toml").context("Could not read Cargo.toml.")?;
    let package = manifest.package.context("Manifest needs to specify [package]")?;

    let cargo_args = [
        "build",
        "--release",
        "--target",
        "wasm32-unknown-unknown",
        "--features",
        "concordium-std/wasm-test",
        "--target-dir",
        "target/concordium",
    ];

    // Output what we are doing so that it is easier to debug if the user
    // has their own features or options.
    eprint!("{} cargo {}", Color::Green.bold().paint("Running"), cargo_args.join(" "));
    if extra_args.is_empty() {
        // This branch is just to avoid the extra trailing space in the case when
        // there are no extra arguments.
        eprintln!()
    } else {
        eprintln!(" {}", extra_args.join(" "));
    }
    let result = Command::new("cargo")
        .args(cargo_args)
        .args(extra_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .context("Failed building contract tests.")?;
    // Make sure that compilation succeeded before proceeding.
    anyhow::ensure!(
        result.status.success(),
        Color::Red.bold().paint("Could not build contract tests.")
    );

    // If we compiled successfully the artifact is in the place listed below.
    // So we load it, and try to run it.s
    let filename = format!(
        "target/concordium/wasm32-unknown-unknown/release/{}.wasm",
        to_snake_case(package.name)
    );

    let wasm = std::fs::read(filename).context("Failed reading contract test output artifact.")?;

    eprintln!("\n{}", Color::Green.bold().paint("Running tests ..."));

    let results = utils::run_module_tests(&wasm)?;
    let mut num_failed = 0;
    for result in results {
        let test_name = result.0;
        match result.1 {
            Some(err) => {
                num_failed += 1;
                eprintln!("  - {} ... {}", test_name, Color::Red.bold().paint("FAILED"));
                eprintln!(
                    "    {} ... {}",
                    Color::Red.bold().paint("Error"),
                    Style::new().italic().paint(err.to_string())
                )
            }
            None => {
                eprintln!("  - {} ... {}", test_name, Color::Green.bold().paint("ok"));
            }
        }
    }

    if num_failed == 0 {
        eprintln!("Test result: {}", Color::Green.bold().paint("ok"));
        Ok(true)
    } else {
        eprintln!("Test result: {}", Color::Red.bold().paint("FAILED"));
        Ok(false)
    }
}
