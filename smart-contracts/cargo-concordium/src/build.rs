use cargo_toml::Manifest;
use contracts_common::*;
use std::{
    fs::read,
    process::{Command, Stdio},
};
use wasmer_interp::generate_contract_schema;

fn to_snake_case(string: String) -> String { string.to_lowercase().replace("-", "_") }

/// Generates the contract schema by compiling with the 'build-schema' feature
/// Then extracts the schema from the schema build
pub fn build_contract_schema() -> Result<schema::Contract, String> {
    let manifest = Manifest::from_path("Cargo.toml")
        .map_err(|err| format!("Failed reading manifest: {}", err))?;
    let package = manifest.package.ok_or("Manifest need to specify [package]")?;

    if !manifest.features.contains_key("build-schema") {
        return Err(String::from(
            "Cargo.toml must contain the 'build-schema' feature to construct the schema

    [features]
    build-schema = []
    ...
",
        ));
    }

    Command::new("cargo")
        .arg("build")
        .args(&["--target", "wasm32-unknown-unknown"])
        .args(&["--features", "build-schema"])
        .args(&["--target-dir", "target/schema"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|err| format!("Failed building contract schemas:\n{}", err))?;

    let filename =
        format!("target/schema/wasm32-unknown-unknown/debug/{}.wasm", to_snake_case(package.name));

    let wasm =
        read(filename).map_err(|err| format!("Failed reading schema contract build:\n{}", err))?;
    let schema = generate_contract_schema(&wasm)?;
    Ok(schema)
}
