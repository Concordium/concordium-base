//! Various utilities for testing and extraction of schemas.

use crate::ExecResult;
use anyhow::{anyhow, bail, ensure, Context};
use concordium_contracts_common::{from_bytes, schema, Cursor, Deserial, Get};
use std::{collections::BTreeMap, default::Default};
use wasm_transform::{
    artifact::{Artifact, ArtifactNamedImport, RunnableCode, TryFromImport},
    machine::{self, NoInterrupt, Value},
    parse::{parse_custom, parse_skeleton},
    types::{ExportDescription, Module, Name},
    utils, validate,
};

#[derive(Debug, Clone, Copy)]
pub enum WasmVersion {
    V0,
    V1,
}

impl std::str::FromStr for WasmVersion {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "V0" | "v0" => Ok(WasmVersion::V0),
            "V1" | "v1" => Ok(WasmVersion::V1),
            _ => anyhow::bail!("Unsupported version: '{}'. Only 'V0' and 'V1' are supported.", s),
        }
    }
}

impl WasmVersion {
    /// Get the version from the cursor. This is not a Serial implementation
    /// since it uses big-endian.
    pub fn read(source: &mut std::io::Cursor<&[u8]>) -> anyhow::Result<WasmVersion> {
        let mut data = [0u8; 4];
        use std::io::Read;
        source.read_exact(&mut data).context("Not enough data to read WasmVersion.")?;
        match u32::from_be_bytes(data) {
            0 => Ok(WasmVersion::V0),
            1 => Ok(WasmVersion::V1),
            n => bail!("Unsupported Wasm version {}.", n),
        }
    }
}

/// A host which traps for any function call.
pub struct TrapHost;

impl<I> machine::Host<I> for TrapHost {
    type Interrupt = NoInterrupt;

    fn tick_initial_memory(&mut self, _num_pages: u32) -> machine::RunResult<()> { Ok(()) }

    fn call(
        &mut self,
        _f: &I,
        _memory: &mut Vec<u8>,
        _stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<Option<NoInterrupt>> {
        bail!("TrapHost traps on all host calls.")
    }
}

/// A host which traps for any function call apart from `report_error` which it
/// prints to standard out.
pub struct TestHost;

impl validate::ValidateImportExport for TestHost {
    /// Simply ensure that there are no duplicates.
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn validate_import_function(
        &self,
        duplicate: bool,
        _mod_name: &Name,
        _item_name: &Name,
        _ty: &wasm_transform::types::FunctionType,
    ) -> bool {
        !duplicate
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn validate_export_function(
        &self,
        _item_name: &Name,
        _ty: &wasm_transform::types::FunctionType,
    ) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
/// An auxiliary datatype used by `report_error` to be able to
/// retain the structured information in case we want to use it later
/// to insert proper links to the file, or other formatting.
pub enum ReportError {
    /// An error reported by `report_error`
    Reported {
        filename: String,
        line:     u32,
        column:   u32,
        msg:      String,
    },
    /// Some other source of error. We only have the description, and no
    /// location.
    Other {
        msg: String,
    },
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Reported {
                filename,
                line,
                column,
                msg,
            } => write!(f, "{}, {}:{}:{}", msg, filename, line, column),
            ReportError::Other {
                msg,
            } => msg.fmt(f),
        }
    }
}

impl machine::Host<ArtifactNamedImport> for TestHost {
    type Interrupt = NoInterrupt;

    fn tick_initial_memory(&mut self, _num_pages: u32) -> machine::RunResult<()> {
        // The test host does not count energy.
        Ok(())
    }

    fn call(
        &mut self,
        f: &ArtifactNamedImport,
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<Option<NoInterrupt>> {
        if f.matches("concordium", "report_error") {
            let column = unsafe { stack.pop_u32() };
            let line = unsafe { stack.pop_u32() };
            let filename_length = unsafe { stack.pop_u32() } as usize;
            let filename_start = unsafe { stack.pop_u32() } as usize;
            let msg_length = unsafe { stack.pop_u32() } as usize;
            let msg_start = unsafe { stack.pop_u32() } as usize;
            ensure!(filename_start + filename_length <= memory.len(), "Illegal memory access.");
            ensure!(msg_start + msg_length <= memory.len(), "Illegal memory access.");
            let msg = std::str::from_utf8(&memory[msg_start..msg_start + msg_length])?.to_owned();
            let filename =
                std::str::from_utf8(&memory[filename_start..filename_start + filename_length])?
                    .to_owned();
            bail!(ReportError::Reported {
                filename,
                line,
                column,
                msg
            })
        } else {
            bail!("Unsupported host function call.")
        }
    }
}

/// Instantiates the module with an external function to report back errors.
/// Then tries to run exported test-functions, which are present if compile with
/// the wasm-test feature.
///
/// The return value is a list of pairs (test_name, result)
/// The result is None if the test passed, or an error message
/// if it failed. The error message is the one reported to by report_error, or
/// some internal invariant violation.
pub fn run_module_tests(module_bytes: &[u8]) -> ExecResult<Vec<(String, Option<ReportError>)>> {
    let artifact = utils::instantiate::<ArtifactNamedImport, _>(&TestHost, module_bytes)?;
    let mut out = Vec::with_capacity(artifact.export.len());
    for name in artifact.export.keys() {
        if let Some(test_name) = name.as_ref().strip_prefix("concordium_test ") {
            let res = artifact.run(&mut TestHost, name, &[]);
            match res {
                Ok(_) => out.push((test_name.to_owned(), None)),
                Err(msg) => {
                    if let Some(err) = msg.downcast_ref::<ReportError>() {
                        out.push((test_name.to_owned(), Some(err.clone())));
                    } else {
                        out.push((
                            test_name.to_owned(),
                            Some(ReportError::Other {
                                msg: msg.to_string(),
                            }),
                        ))
                    }
                }
            };
        }
    }
    Ok(out)
}

/// Tries to generate a state schema and schemas for parameters of methods of a
/// V0 contract.
pub fn generate_contract_schema_v0(module_bytes: &[u8]) -> ExecResult<schema::ModuleV0> {
    let artifact = utils::instantiate::<ArtifactNamedImport, _>(&TestHost, module_bytes)?;

    let mut contract_schemas = BTreeMap::new();

    for name in artifact.export.keys() {
        if let Some(contract_name) = name.as_ref().strip_prefix("concordium_schema_state_") {
            let schema_type = generate_schema_run(&artifact, name.as_ref())?;

            // Get the mutable reference to the contract schema, or make a new empty one if
            // an entry does not yet exist.
            let contract_schema = contract_schemas
                .entry(contract_name.to_owned())
                .or_insert_with(schema::ContractV0::default);

            contract_schema.state = Some(schema_type);
        } else if let Some(rest) = name.as_ref().strip_prefix("concordium_schema_function_") {
            if let Some(contract_name) = rest.strip_prefix("init_") {
                let schema_type = generate_schema_run(&artifact, name.as_ref())?;

                let contract_schema = contract_schemas
                    .entry(contract_name.to_owned())
                    .or_insert_with(schema::ContractV0::default);
                contract_schema.init = Some(schema_type);
            } else if rest.contains('.') {
                let schema_type = generate_schema_run(&artifact, name.as_ref())?;

                // Generates receive-function parameter schema type
                let split_name: Vec<_> = rest.splitn(2, '.').collect();
                let contract_name = split_name[0];
                let function_name = split_name[1];

                let contract_schema = contract_schemas
                    .entry(contract_name.to_owned())
                    .or_insert_with(schema::ContractV0::default);

                contract_schema.receive.insert(function_name.to_owned(), schema_type);
            } else {
                // do nothing, some other function that is neither init nor
                // receive.
            }
        }
    }

    Ok(schema::ModuleV0 {
        contracts: contract_schemas,
    })
}

/// Tries to generate schemas for parameters and return values of methods for a
/// versioned module v0.
pub fn generate_contract_schema_versioned_v0(
    module_bytes: &[u8],
) -> ExecResult<schema::VersionedModuleSchema> {
    let artifact = utils::instantiate::<ArtifactNamedImport, _>(&TestHost, module_bytes)?;

    let mut contract_schemas = BTreeMap::new();

    for name in artifact.export.keys() {
        if let Some(rest) = name.as_ref().strip_prefix("concordium_schema_function_") {
            if let Some(contract_name) = rest.strip_prefix("init_") {
                let function_schema = generate_schema_run(&artifact, name.as_ref())?;

                let contract_schema = contract_schemas
                    .entry(contract_name.to_owned())
                    .or_insert_with(schema::ContractV1::default);
                contract_schema.init = Some(function_schema);
            } else if rest.contains('.') {
                let function_schema = generate_schema_run(&artifact, name.as_ref())?;

                // Generates receive-function parameter schema type
                let split_name: Vec<_> = rest.splitn(2, '.').collect();
                let contract_name = split_name[0];
                let function_name = split_name[1];

                let contract_schema = contract_schemas
                    .entry(contract_name.to_owned())
                    .or_insert_with(schema::ContractV1::default);

                contract_schema.receive.insert(function_name.to_owned(), function_schema);
            } else {
                // do nothing, some other function that is neither init nor
                // receive.
            }
        }
    }

    Ok(schema::VersionedModuleSchema::V1(schema::ModuleV1 {
        contracts: contract_schemas,
    }))
}

/// Runs the given schema function and reads the resulting function schema from
/// memory, attempting to parse it. If this fails, an error is returned.
fn generate_schema_run<I: TryFromImport, C: RunnableCode, SchemaType: Deserial>(
    artifact: &Artifact<I, C>,
    schema_fn_name: &str,
) -> ExecResult<SchemaType> {
    let (ptr, memory) = if let machine::ExecutionOutcome::Success {
        result: Some(Value::I32(ptr)),
        memory,
    } = artifact.run(&mut TrapHost, schema_fn_name, &[])?
    {
        (ptr as u32 as usize, memory)
    } else {
        bail!("Schema derivation function is malformed.")
    };

    // First we read an u32 which is the length of the serialized schema
    ensure!(ptr + 4 <= memory.len(), "Illegal memory access.");
    let len = u32::deserial(&mut Cursor::new(&memory[ptr..ptr + 4]))
        .map_err(|_| anyhow!("Cannot read schema length."))?;

    // Read the schema with offset of the u32
    ensure!(ptr + 4 + len as usize <= memory.len(), "Illegal memory access when reading schema.");
    let schema_bytes = &memory[ptr + 4..ptr + 4 + len as usize];
    SchemaType::deserial(&mut Cursor::new(schema_bytes))
        .map_err(|_| anyhow!("Failed deserialising the schema."))
}

/// Get the init methods of the module.
pub fn get_inits(module: &Module) -> Vec<&Name> {
    let mut out = Vec::new();
    for export in module.export.exports.iter() {
        if export.name.as_ref().starts_with("init_") && !export.name.as_ref().contains('.') {
            if let ExportDescription::Func {
                ..
            } = export.description
            {
                out.push(&export.name);
            }
        }
    }
    out
}

/// Get the receive methods of the module.
pub fn get_receives(module: &Module) -> Vec<&Name> {
    let mut out = Vec::new();
    for export in module.export.exports.iter() {
        if export.name.as_ref().contains('.') {
            if let ExportDescription::Func {
                ..
            } = export.description
            {
                out.push(&export.name);
            }
        }
    }
    out
}

/// Get the embedded schema if it exists
pub fn get_embedded_schema_v0(bytes: &[u8]) -> ExecResult<schema::ModuleV0> {
    let skeleton = parse_skeleton(bytes)?;
    let mut schema_sections = Vec::new();
    for ucs in skeleton.custom.iter() {
        let cs = parse_custom(ucs)?;
        if cs.name.as_ref() == "concordium-schema-v1" {
            schema_sections.push(cs)
        }
    }
    let section =
        schema_sections.first().ok_or_else(|| anyhow!("No schema found in the module"))?;
    let source = &mut Cursor::new(section.contents);
    source.get().map_err(|_| anyhow!("Failed parsing schema"))
}

/// Get the embedded schema if it exists.
/// It will attempt to use the schema in the custom section "concordium-schema"
/// and if this is not present it will try to use the custom section
/// "concordium-schema-v2".
pub fn get_embedded_schema_versioned(bytes: &[u8]) -> ExecResult<schema::VersionedModuleSchema> {
    let skeleton = parse_skeleton(bytes)?;
    let mut schema_v2_section = None;
    let mut schema_versioned_section = None;
    for ucs in skeleton.custom.iter() {
        let cs = parse_custom(ucs)?;
        if cs.name.as_ref() == "concordium-schema" && schema_versioned_section.is_none() {
            schema_versioned_section = Some(cs)
        } else if cs.name.as_ref() == "concordium-schema-v2" && schema_v2_section.is_none() {
            schema_v2_section = Some(cs)
        }
    }

    if let Some(cs) = schema_versioned_section {
        let module: schema::VersionedModuleSchema =
            from_bytes(&cs.contents).map_err(|_| anyhow!("Failed parsing schema"))?;
        Ok(module)
    } else if let Some(cs) = schema_v2_section {
        let module = from_bytes(&cs.contents).map_err(|_| anyhow!("Failed parsing schema"))?;
        Ok(schema::VersionedModuleSchema::V1(module))
    } else {
        bail!("No schema found in the module")
    }
}
