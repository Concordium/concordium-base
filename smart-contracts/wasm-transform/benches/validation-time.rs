use concordium_wasm::{
    artifact::ArtifactNamedImport,
    validate::{ValidateImportExport, ValidationConfig},
    *,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const VALIDATION_TIME_PRESERVE: &[u8] =
    include_bytes!("../../testdata/validation-time-preserve.wasm");

const VALIDATION_TIME_CONSUME: &[u8] =
    include_bytes!("../../testdata/validation-time-consume.wasm");

pub struct NoImports;

impl ValidateImportExport for NoImports {
    fn validate_import_function(
        &self,
        _duplicate: bool,
        _mod_name: &types::Name,
        _item_name: &types::Name,
        _ty: &types::FunctionType,
    ) -> bool {
        false
    }

    fn validate_export_function(
        &self,
        _item_name: &types::Name,
        _ty: &types::FunctionType,
    ) -> bool {
        false
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("validation-time/preserve", |b| {
        b.iter(|| {
            black_box(utils::instantiate_with_metering::<ArtifactNamedImport>(
                ValidationConfig::V1,
                CostConfigurationV1,
                &NoImports,
                VALIDATION_TIME_PRESERVE,
            ))
        })
    });
    c.bench_function("validation-time/consume", |b| {
        b.iter(|| {
            black_box(utils::instantiate_with_metering::<ArtifactNamedImport>(
                ValidationConfig::V1,
                CostConfigurationV1,
                &NoImports,
                VALIDATION_TIME_CONSUME,
            ))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
