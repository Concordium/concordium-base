use ansi_term::{Color, Style};
use anyhow::Context;
use cargo_toml::Manifest;
use concordium_contracts_common::*;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};
use wasm_chain_integration::{utils, v0};
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
) -> anyhow::Result<usize> {
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

    validate_module(&v0::ConcordiumAllowedImports, &skeleton)
        .context("Could not validate resulting smart contract module.")?;

    let mut output_bytes = Vec::new();

    // Embed schema custom section
    if let Some(schema) = embed_schema {
        let schema_bytes = to_bytes(schema);

        let custom_section = CustomSection {
            name:     Name {
                name: String::from("concordium-schema-v1"),
            },
            contents: &schema_bytes,
        };

        skeleton.output(&mut output_bytes)?;
        write_custom_section(&mut output_bytes, &custom_section)?;
    } else {
        skeleton.output(&mut output_bytes)?;
    }

    let out_filename = out.unwrap_or_else(|| PathBuf::from(filename));
    let total_module_len = output_bytes.len();
    fs::write(out_filename, output_bytes)?;
    Ok(total_module_len)
}

/// Generates the contract schema by compiling with the 'build-schema' feature
/// Then extracts the schema from the schema build
pub fn build_contract_schema(cargo_args: &[String]) -> anyhow::Result<schema::Module> {
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
    let schema = utils::generate_contract_schema(&wasm)
        .context("Could not generate module schema from Wasm module.")?;
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
