//! Common utilities for Wasm transformations. These are wrappers around the
//! basic functionality exposed by other modules.

use crate::{
    artifact::{Artifact, CompiledFunction, CompiledFunctionBytes, TryFromImport},
    parse::{parse_skeleton, GetParseable, Parseable, Skeleton},
    validate::{validate_module, ValidateImportExport, ValidationConfig},
};

/// Strip the custom sections from the module Wasm module.
pub fn strip(skeleton: &mut Skeleton<'_>) { skeleton.custom = Vec::new(); }

/// The result of module instantiation. The type parameter `I` indicates how
/// imports are represented in the artifact, and will typically have to
/// implement [`TryFromImport`].
#[derive(Debug)]
pub struct InstantiatedModule<I> {
    /// The size of custom sections that were dropped from the module.
    pub custom_sections_size: u64,
    /// The compiled artifact.
    pub artifact:             Artifact<I, CompiledFunction>,
}

/// Parse a Wasm module, validate, and compile to a runnable artifact.
pub fn instantiate<I: TryFromImport, VI: ValidateImportExport>(
    config: ValidationConfig,
    imp: &VI,
    bytes: &[u8],
) -> anyhow::Result<InstantiatedModule<I>> {
    let skeleton = parse_skeleton(bytes)?;
    let custom_sections_size = skeleton.custom_sections_size();
    let artifact = validate_module(config, imp, &skeleton)?.compile()?;
    Ok(InstantiatedModule {
        custom_sections_size,
        artifact,
    })
}

/// Parse a Wasm module, validate, inject metering, and compile to a runnable
/// artifact.
pub fn instantiate_with_metering<I: TryFromImport, VI: ValidateImportExport>(
    config: ValidationConfig,
    imp: &VI,
    bytes: &[u8],
) -> anyhow::Result<InstantiatedModule<I>> {
    let skeleton = parse_skeleton(bytes)?;
    let custom_sections_size = skeleton.custom_sections_size();
    let mut module = validate_module(config, imp, &skeleton)?;
    module.inject_metering()?;
    let artifact = module.compile()?;
    Ok(InstantiatedModule {
        custom_sections_size,
        artifact,
    })
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
/// Parse an artifact from an array of bytes. This does as much zero-copy
/// deserialization as possible. In particular the function bodies are not
/// deserialized and are simply retained as references into the original array.
///
/// This function is designed to only be used on trusted sources and is not
/// guaranteed to not use excessive resources if used on untrusted ones.
pub fn parse_artifact<'a, I: Parseable<'a, ()>>(
    bytes: &'a [u8],
) -> anyhow::Result<Artifact<I, CompiledFunctionBytes<'a>>> {
    (&mut std::io::Cursor::new(bytes)).next(())
}
