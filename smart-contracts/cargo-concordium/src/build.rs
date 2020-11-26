use ansi_term::{Color, Style};
use anyhow::Context;
use cargo_toml::Manifest;
use contracts_common::*;
use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
};
use wasm_chain_integration::{
    generate_contract_schema, run_module_tests, ConcordiumAllowedImports,
};
use wasm_transform::{
    output::{write_custom_section, Output},
    parse::parse_skeleton,
    types::{CustomSection, Name},
    utils::strip,
    validate::validate_module,
};

fn to_snake_case(string: String) -> String { string.to_lowercase().replace("-", "_") }

pub fn build_contract(
    embed_schema: &Option<schema::Module>,
    out: Option<PathBuf>,
    cargo_args: &[String],
) -> anyhow::Result<()> {
    let manifest = Manifest::from_path("Cargo.toml")
        .map_err(|err| anyhow::anyhow!("Failed reading manifest: {}", err))?;
    let package =
        manifest.package.ok_or_else(|| anyhow::anyhow!("Manifest need to specify [package]"))?;

    Command::new("cargo")
        .arg("build")
        .args(&["--target", "wasm32-unknown-unknown"])
        .args(&["--release"])
        .args(&["--target-dir", "target/concordium"])
        .args(cargo_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|err| anyhow::anyhow!("Failed building contract:\n{}", err))?;

    let filename = format!(
        "target/concordium/wasm32-unknown-unknown/release/{}.wasm",
        to_snake_case(package.name)
    );

    let mut wasm_file = File::open(&filename)?;
    let mut wasm = vec![];
    wasm_file.read_to_end(&mut wasm)?;

    let mut skeleton =
        parse_skeleton(&wasm).map_err(|err| anyhow::anyhow!("Failed parsing skeleton: {}", err))?;

    // Remove all custom sections to reduce the size of the module
    strip(&mut skeleton);

    validate_module(&ConcordiumAllowedImports, &skeleton)?;

    let out_filename = out.unwrap_or_else(|| PathBuf::from(filename));

    let mut wasm_file = File::create(&out_filename)?;

    // Embed schema custom section
    if let Some(schema) = embed_schema {
        let schema_bytes = to_bytes(schema);

        let custom_section = CustomSection {
            name:     Name {
                name: String::from("concordium-schema-v1"),
            },
            contents: &schema_bytes,
        };

        skeleton.output(&mut wasm_file)?;
        write_custom_section(&mut wasm_file, &custom_section)?;
    } else {
        skeleton.output(&mut wasm_file)?;
    }

    Ok(())
}

/// Generates the contract schema by compiling with the 'build-schema' feature
/// Then extracts the schema from the schema build
pub fn build_contract_schema(cargo_args: &[String]) -> anyhow::Result<schema::Module> {
    let manifest =
        Manifest::from_path("Cargo.toml").context("Failed reading Cargo.toml manifest.")?;

    let package =
        manifest.package.ok_or_else(|| anyhow::anyhow!("Manifest needs to specify [package]"))?;

    anyhow::ensure!(
        manifest.features.contains_key("build-schema"),
        "Cargo.toml must contain the 'build-schema' feature to construct the schema

    [features]
    build-schema = []
    ...
"
    );

    Command::new("cargo")
        .arg("build")
        .args(&["--target", "wasm32-unknown-unknown"])
        .arg("--release")
        .args(&["--features", "build-schema"])
        .args(&["--target-dir", "target/concordium"])
        .args(cargo_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| "Failed building contract schemas.")?;

    let filename = format!(
        "target/concordium/wasm32-unknown-unknown/release/{}.wasm",
        to_snake_case(package.name)
    );

    let wasm = std::fs::read(filename).context("Failed reading contract schema output artifact")?;
    let schema = generate_contract_schema(&wasm)?;
    Ok(schema)
}

/// Build tests and run them. If errors occur in building the tests, or there
/// are runtime exceptions that are not expected then this function returns
/// Err(...).
///
/// Otherwise a boolean is returned, signifying whether the tests succeeded or
/// failed.
pub fn build_and_run_wasm_test(extra_args: &[String]) -> anyhow::Result<bool> {
    let manifest =
        Manifest::from_path("Cargo.toml").context("Failed reading Cargo.toml manifest.")?;
    let package =
        manifest.package.ok_or_else(|| anyhow::anyhow!("Manifest needs to specify [package]"))?;

    anyhow::ensure!(
        manifest.features.contains_key("wasm-test"),
        "Cargo.toml must contain the 'wasm-test' feature to construct the test build

    [features]
    wasm-test = []
    ...
"
    );

    let mut cargo_args = Vec::new();
    cargo_args.push("build");
    cargo_args.extend_from_slice(&["--target", "wasm32-unknown-unknown"]);
    cargo_args.extend_from_slice(&["--features", "wasm-test"]);
    cargo_args.extend_from_slice(&["--target-dir", "target/wasm-test"]);

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
        .with_context(|| "Failed building contract tests.")?;
    // Make sure that compilation succeeded before proceeding.
    anyhow::ensure!(
        result.status.success(),
        Color::Red.bold().paint("Could not build contract tests.")
    );

    // If we compiled successfully the artifact is in the place listed below.
    // So we load it, and try to run it.s
    let filename = format!(
        "target/wasm-test/wasm32-unknown-unknown/debug/{}.wasm",
        to_snake_case(package.name)
    );

    let wasm = std::fs::read(filename).context("Failed reading contract test output artifact.")?;

    eprintln!("\n{}", Color::Green.bold().paint("Running tests ..."));

    let results = run_module_tests(&wasm)?;
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
