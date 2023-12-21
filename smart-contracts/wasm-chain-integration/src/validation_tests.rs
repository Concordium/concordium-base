/* This module tests the use of _constant_ global offsets in data and elem
 * sections. Additionally, it ensures that globals can only be initialized by
 * constants.
 *
 * To compile the invalid modules with wat2wasm, use the --no-check option.
 */

use crate::v0::ProcessedImports;
use concordium_wasm::{utils::instantiate, validate::ValidationConfig};

#[test]
fn global_offset_test() {
    // This module uses _constant_ global offsets for both data and elem sections.
    let contract = std::fs::read("../testdata/contracts/global-offset-test.wasm").unwrap();
    let res = instantiate::<ProcessedImports, _>(
        ValidationConfig::V0,
        &crate::v0::ConcordiumAllowedImports,
        &contract,
    );
    assert!(res.is_ok(), "Mutable global offsets allowed in data and elem sections: {:?}", res);
}

#[test]
fn mut_global_offset_test() {
    // This module tries to use _mutable_ global offsets for both data and elem
    // sections.
    let contract = std::fs::read("../testdata/contracts/mut-global-offset-test.wasm").unwrap();
    let res = instantiate::<ProcessedImports, _>(
        ValidationConfig::V0,
        &crate::v0::ConcordiumAllowedImports,
        &contract,
    );

    assert!(res.is_err(), "Mutable global offsets _not_ allowed in data and elem sections.");
}

#[test]
fn init_global_with_ref_test() {
    // This module tries to instantiate globals using references to other globals.
    let contract = std::fs::read("../testdata/contracts/init-global-with-ref-test.wasm").unwrap();
    let res = instantiate::<ProcessedImports, _>(
        ValidationConfig::V0,
        &crate::v0::ConcordiumAllowedImports,
        &contract,
    );
    assert!(res.is_err(), "Globals cannot be initialized with references to other globals.");
}

#[test]
fn init_data_with_global_offset() {
    // This module tries to use globals in data section offsets.
    // This used to be allowed according to our specification, but is disallowed
    // from protocol 6 onward.
    let contract = std::fs::read("../testdata/contracts/global-data-section-test.wasm").unwrap();
    let res = instantiate::<ProcessedImports, _>(
        ValidationConfig::V0,
        &crate::v1::ConcordiumAllowedImports {
            support_upgrade: true,
            enable_debug:    false,
        },
        &contract,
    );
    assert!(res.is_ok(), "Globals can be used in V0 data section validation.");
    let res = instantiate::<ProcessedImports, _>(
        ValidationConfig::V1,
        &crate::v1::ConcordiumAllowedImports {
            support_upgrade: true,
            enable_debug:    false,
        },
        &contract,
    );
    assert!(res.is_err(), "Globals cannot be used in V1 data section validation.");
}

#[test]
fn init_element_with_global_offset() {
    // This module tries to use globals in element section offsets.
    // This used to be allowed according to our specification, but is disallowed
    // from protocol 6 onward.
    let contract = std::fs::read("../testdata/contracts/global-element-section-test.wasm").unwrap();
    let res = instantiate::<ProcessedImports, _>(
        ValidationConfig::V0,
        &crate::v1::ConcordiumAllowedImports {
            support_upgrade: true,
            enable_debug:    false,
        },
        &contract,
    );
    assert!(res.is_ok(), "Globals can be used in V0 element section validation.");
    let res = instantiate::<ProcessedImports, _>(
        ValidationConfig::V1,
        &crate::v1::ConcordiumAllowedImports {
            support_upgrade: true,
            enable_debug:    false,
        },
        &contract,
    );
    assert!(res.is_err(), "Globals cannot be used in V1 element section validation.");
}
