//! Common utilities.

use crate::{
    artifact::{compile_module, Artifact, CompiledFunction, TryFromImport},
    parse::{parse_skeleton, Skeleton},
    validate::validate_module,
};

/// Strip the custom sections from the module.
pub fn strip<'a>(skeleton: &mut Skeleton<'a>) { skeleton.custom = Vec::new(); }

/// Parse, validate, and compile to a runnable artifact.
pub fn instantiate<I: TryFromImport>(
    bytes: &[u8],
) -> anyhow::Result<Artifact<I, CompiledFunction>> {
    let module = validate_module(&parse_skeleton(bytes)?)?;
    compile_module(module)
}

/// Parse, validate, inject metering, and compile to a runnable artifact.
pub fn instantiate_with_metering<I: TryFromImport>(
    bytes: &[u8],
) -> anyhow::Result<Artifact<I, CompiledFunction>> {
    let mut module = validate_module(&parse_skeleton(bytes)?)?;
    module.inject_metering()?;
    compile_module(module)
}
