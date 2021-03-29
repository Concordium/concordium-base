#![no_main]

use libfuzzer_sys::fuzz_target;
use wasm_chain_integration::fuzz::*;

use wasm_chain_integration::{get_inits, get_receives, invoke_init, invoke_receive, types::*};
use wasm_transform::{
    artifact::{Artifact, CompiledFunctionBytes},
    output::Output,
    parse::parse_skeleton,
    types::Name,
    utils::parse_artifact,
    validate::validate_module,
};

const ENERGY: u64 = 10_000_000;
const CONFIG: PrintConfig = PrintConfig {
    print_success:                    false,
    print_failure:                    false,
    print_module_before_interpreting: false,
    print_failing_module:             false,
};

fuzz_target!(|input: RandomizedInterpreterInput<InterpreterConfig>| {
    let RandomizedInterpreterInput {
        amount,
        module,
        init_ctx,
        receive_ctx,
        state,
        parameter,
    } = input;
    let wasm_bytes: Vec<u8> = module.to_bytes();
    let bytes = &wasm_bytes[..];
    if CONFIG.print_module_before_interpreting {
        print_module(&bytes);
    }
    let maybe_module = validate_module(&ConcordiumAllowedImports, &parse_skeleton(&bytes).unwrap());
    match maybe_module {
        Ok(mut module) => {
            module.inject_metering().unwrap();
            let init_names: Vec<Name> = get_inits(&module).into_iter().cloned().collect();
            let receive_names: Vec<Name> = get_receives(&module).into_iter().cloned().collect();
            let artifact = module.compile().expect("Compilation of validated module failed.");
            // Ensuring that artifact can be serialized and deserialized
            let mut out_buf = Vec::new();
            artifact.output(&mut out_buf).unwrap();
            let _artifact: Artifact<ProcessedImports, CompiledFunctionBytes> =
                parse_artifact(&out_buf).unwrap();
            for init_name in init_names {
                process(
                    invoke_init(
                        &artifact,
                        amount,
                        init_ctx.clone(),
                        &init_name.name,
                        parameter.as_slice(),
                        ENERGY,
                    ),
                    &bytes,
                    CONFIG,
                );
            }
            for receive_name in receive_names {
                process(
                    invoke_receive(
                        &artifact,
                        amount,
                        receive_ctx.clone(),
                        &state,
                        &receive_name.name,
                        parameter.as_slice(),
                        ENERGY,
                    ),
                    &bytes,
                    CONFIG,
                );
            }
        }
        _ => (),
    }
});
