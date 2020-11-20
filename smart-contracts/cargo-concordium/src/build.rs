use cargo_toml::Manifest;
use contracts_common::*;
use std::{
    fs::{read, File},
    io::Read,
    process::{Command, Stdio},
};
use wasm_chain_integration::{generate_contract_schema, ConcordiumAllowedImports};
use wasm_transform::{
    output::{write_custom_section, Output},
    parse::parse_skeleton,
    types::{CustomSection, Name},
    utils::strip,
    validate::validate_module,
};

fn to_snake_case(string: String) -> String { string.to_lowercase().replace("-", "_") }

pub fn build_contract(embed_schema: Option<schema::Module>) -> anyhow::Result<()> {
    let manifest = Manifest::from_path("Cargo.toml")
        .map_err(|err| anyhow::anyhow!("Failed reading manifest: {}", err))?;
    let package =
        manifest.package.ok_or_else(|| anyhow::anyhow!("Manifest need to specify [package]"))?;

    Command::new("cargo")
        .arg("build")
        .args(&["--target", "wasm32-unknown-unknown"])
        .args(&["--release"])
        .args(&["--target-dir", "target/concordium"])
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

    let mut wasm_file = File::create(&filename)?;

    // Embed schema custom section
    if let Some(schema) = embed_schema {
        let schema_bytes = to_bytes(&schema);

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
pub fn build_contract_schema() -> anyhow::Result<schema::Module> {
    let manifest = Manifest::from_path("Cargo.toml")
        .map_err(|err| anyhow::anyhow!("Failed reading manifest: {}", err))?;
    let package =
        manifest.package.ok_or_else(|| anyhow::anyhow!("Manifest need to specify [package]"))?;

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
        .args(&["--features", "build-schema"])
        .args(&["--target-dir", "target/schema"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|err| anyhow::anyhow!("Failed building contract schemas:\n{}", err))?;

    let filename =
        format!("target/schema/wasm32-unknown-unknown/debug/{}.wasm", to_snake_case(package.name));

    let wasm = read(filename)
        .map_err(|err| anyhow::anyhow!("Failed reading schema contract build:\n{}", err))?;
    let schema = generate_contract_schema(&wasm)?;
    Ok(schema)
}
