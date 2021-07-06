//! Common utilities for Wasm transformations. These are wrappers around the
//! basic functionality exposed by other modules.

use crate::{
    artifact::{Artifact, CompiledFunction, CompiledFunctionBytes, TryFromImport},
    parse::{parse_skeleton, GetParseable, Parseable, Skeleton},
    validate::{validate_module, ValidateImportExport},
};

/// Strip the custom sections from the module.
pub fn strip(skeleton: &mut Skeleton<'_>) { skeleton.custom = Vec::new(); }

/// Parse, validate, and compile to a runnable artifact.
pub fn instantiate<I: TryFromImport, VI: ValidateImportExport>(
    imp: &VI,
    bytes: &[u8],
) -> anyhow::Result<Artifact<I, CompiledFunction>> {
    validate_module(imp, &parse_skeleton(bytes)?)?.compile()
}

/// Parse, validate, inject metering, and compile to a runnable artifact.
pub fn instantiate_with_metering<I: TryFromImport, VI: ValidateImportExport>(
    imp: &VI,
    bytes: &[u8],
) -> anyhow::Result<Artifact<I, CompiledFunction>> {
    let mut module = validate_module(imp, &parse_skeleton(bytes)?)?;
    module.inject_metering()?;
    module.compile()
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
