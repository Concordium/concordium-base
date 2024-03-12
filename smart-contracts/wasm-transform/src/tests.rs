//! Test correctness of instruction execution.
//! Currently this tests only the sign extension instructions.
use crate::{
    artifact::ArtifactNamedImport,
    machine::{Host, NoInterrupt},
    utils::instantiate,
    validate::{ValidateImportExport, ValidationConfig},
};

// A dummy host which does not allow any host functions, and allows any export
// function.
struct TestHost;

impl ValidateImportExport for TestHost {
    fn validate_import_function(
        &self,
        _duplicate: bool,
        _mod_name: &crate::types::Name,
        _item_name: &crate::types::Name,
        _ty: &crate::types::FunctionType,
    ) -> bool {
        false
    }

    fn validate_export_function(
        &self,
        _item_name: &crate::types::Name,
        _ty: &crate::types::FunctionType,
    ) -> bool {
        true
    }
}

impl<I> Host<I> for TestHost {
    type Interrupt = NoInterrupt;

    // In this test, we don't care about charging for execution, so we do nothing.
    fn tick_initial_memory(&mut self, _num_pages: u32) -> crate::machine::RunResult<()> { Ok(()) }

    // Do not allow any external calls.
    // In particular this means that this host cannot be used after the metering
    // transformation.
    fn call(
        &mut self,
        _f: &I,
        _memory: &mut Vec<u8>,
        _stack: &mut crate::machine::RuntimeStack,
    ) -> crate::machine::RunResult<Option<Self::Interrupt>> {
        unimplemented!("No imports are allowed, so this can never be called in tests.")
    }

    fn tick_energy(&mut self, _energy: u64) -> crate::machine::RunResult<()> { unimplemented!() }

    fn track_call(&mut self) -> crate::machine::RunResult<()> { unimplemented!() }

    fn track_return(&mut self) { unimplemented!() }
}

#[test]
// Make sure the interpreter correctly executes sign extension instructions.
fn test_sign_extension() -> anyhow::Result<()> {
    let source = include_bytes!("../testdata/sign-ext-instructions.wasm");

    let artifact =
        instantiate::<ArtifactNamedImport, _>(ValidationConfig::V1, &TestHost, source)?.artifact;
    // Make sure there is no assertion violation, which would be a runtime error,
    // leading to an Err result below.
    artifact.run(&mut TestHost, "check_sign_extend_instructions", &[])?;

    Ok(())
}
