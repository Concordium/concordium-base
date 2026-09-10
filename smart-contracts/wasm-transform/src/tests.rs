//! Test correctness of instruction execution.
//! Currently this tests only the sign extension instructions.
use crate::utils::instantiate_with_metering;
use crate::{
    artifact::ArtifactNamedImport,
    artifact_disassembler,
    machine::{Host, NoInterrupt},
    utils::instantiate,
    validate::{ValidateImportExport, ValidationConfig},
    CostConfigurationV1,
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
    fn tick_initial_memory(&mut self, _num_pages: u32) -> crate::machine::RunResult<()> {
        Ok(())
    }

    // Do not allow any external calls.
    // In particular this means that this host cannot be used after the metering
    // transformation.
    fn call(
        &mut self,
        _f: &I,
        _memory: &mut [u8],
        _stack: &mut crate::machine::RuntimeStack,
    ) -> crate::machine::RunResult<Option<Self::Interrupt>> {
        unimplemented!("No imports are allowed, so this can never be called in tests.")
    }

    fn tick_energy(&mut self, _energy: u64) -> crate::machine::RunResult<()> {
        // Do nothing.
        Ok(())
    }

    fn track_call(&mut self) -> crate::machine::RunResult<()> {
        // do nothing in this test host.
        Ok(())
    }

    fn track_return(&mut self) {
        // do nothing in this test host.
    }
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

/// Test that the interpreter rejects execution paths that executes too many copy instructions
/// compared to the energy they tick.
#[test]
fn test_copy_instruction_limit() {
    let source = include_bytes!("../testdata/copy-runtime-metering.wasm");

    let artifact = instantiate_with_metering::<ArtifactNamedImport>(
        ValidationConfig::V1,
        CostConfigurationV1,
        &TestHost,
        source,
    )
    .unwrap()
    .artifact;

    println!("{}", artifact_disassembler::disassemble_artifact(&artifact));

    artifact.run(&mut TestHost, "add_and_copy", &[]).unwrap();
    artifact
        .run(&mut TestHost, "add_and_copy_10", &[])
        .map(|_| ())
        .expect_err("too many copy operations");
    artifact
        .run(&mut TestHost, "only_copy", &[])
        .map(|_| ())
        .expect_err("too many copy operations");
    artifact
        .run(&mut TestHost, "only_copy_10", &[])
        .map(|_| ())
        .expect_err("too many copy operations");
    artifact.run(&mut TestHost, "loop_copy", &[]).unwrap();
    artifact
        .run(&mut TestHost, "loop_copy_10", &[])
        .map(|_| ())
        .expect_err("too many copy operations");

}
