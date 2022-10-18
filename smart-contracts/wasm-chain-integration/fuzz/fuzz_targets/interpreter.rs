#![no_main]

/// Fuzz target for the Wasm smart-contract interpreter to test parsing,
/// validation, metering injection, Wasm code generation, and init/receive
/// function execution.
use libfuzzer_sys::fuzz_target;
use wasm_chain_integration::fuzz::*;

use wasm_chain_integration::*;
use wasm_transform::{
    artifact::{Artifact, CompiledFunctionBytes},
    output::Output,
    parse::parse_skeleton,
    types::Name,
    utils::parse_artifact,
    validate::validate_module,
};

/// The energy limit on the mainnet is 3 mln NRG. However, we increase the limit
/// to 10 mln here in order to allow the interpreter to potentially explore more
/// execution paths. This should roughly correspond to a maximum execution time
/// of 10 seconds.
const ENERGY: u64 = 10_000_000;
/// A configuration object to set what information should be printed while
/// fuzzing.
const CONFIG: PrintConfig = PrintConfig {
    /// Report when a module was successfully compiled and finished executing
    /// without errors.
    print_success:                    false,
    /// Report when a module compilation or execution resulted in an error.
    print_failure:                    false,
    /// Always print out a module in .wat format before it is passed to the
    /// interpreter.
    print_module_before_interpreting: false,
    /// Print out a module in .wat format, but only if it resulted in a
    /// compilation or runtime error.
    print_failing_module:             false,
};

// Creates a random, but type-correct Wasm module, along with a random
// - amount to pass to the init/receive function
// - init and receive context
// - smart-contract state
// - parameter to the receive function.
// This generated data is used to validate, insert metering, and compile the
// generated module, and execute all its init and receive functions. We also
// test that the generated artifact can be (de)serialized.
// If any of those steps fail, this code will crash, and the fuzzer will report
// it.
//
// Note that this code will execute all the functions generated in the smart
// contract because the module creates an auxiliary receive function for all
// functions.
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
