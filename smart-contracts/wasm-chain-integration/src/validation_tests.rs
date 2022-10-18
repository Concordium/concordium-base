/* This module tests the use of _constant_ global offsets in data and elem
 * sections. Additionally, it ensures that globals can only be initialized by
 * constants.
 *
 * To compile the invalid modules with wat2wasm, use the --no-check option.
 */

use wasm_transform::{
    artifact::{Artifact, CompiledFunction},
    utils::instantiate,
};

use crate::v0::ProcessedImports;

#[test]
fn global_offset_test() {
    // This module uses _constant_ global offsets for both data and elem sections.
    let contract = std::fs::read("../testdata/contracts/global-offset-test.wasm").unwrap();
    let res: anyhow::Result<Artifact<ProcessedImports, CompiledFunction>> =
        instantiate(&crate::v0::ConcordiumAllowedImports, &contract);
    assert!(res.is_ok(), "Mutable global offsets allowed in data and elem sections: {:?}", res);
}

#[test]
fn mut_global_offset_test() {
    // This module tries to use _mutable_ global offsets for both data and elem
    // sections.
    let contract = std::fs::read("../testdata/contracts/mut-global-offset-test.wasm").unwrap();
    let res: anyhow::Result<Artifact<ProcessedImports, CompiledFunction>> =
        instantiate(&crate::v0::ConcordiumAllowedImports, &contract);

    assert!(res.is_err(), "Mutable global offsets _not_ allowed in data and elem sections.");
}

#[test]
fn init_global_with_ref_test() {
    // This module tries to instantiate globals using references to other globals.
    let contract = std::fs::read("../testdata/contracts/init-global-with-ref-test.wasm").unwrap();
    let res: anyhow::Result<Artifact<ProcessedImports, CompiledFunction>> =
        instantiate(&crate::v0::ConcordiumAllowedImports, &contract);
    assert!(res.is_err(), "Globals cannot be initialized with references to other globals.");
}
