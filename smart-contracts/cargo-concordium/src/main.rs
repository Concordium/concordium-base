use crate::{build::*, schema_json::*};
use clap::AppSettings;
use contracts_common::{from_bytes, to_bytes};
use std::{
    fs,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::exit,
};
use structopt::StructOpt;
use wasm_chain_integration::*;

mod build;
mod schema_json;

#[derive(Debug, StructOpt)]
#[structopt(bin_name = "cargo")]
enum CargoCommand {
    #[structopt(name = "concordium")]
    Concordium(Command),
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Smart contract development tool for building, testing and deploying.")]
enum Command {
    #[structopt(
        name = "run",
        about = "Locally simulate invocation method of a smart contract and inspect the state."
    )]
    Run(RunCommand),

    #[structopt(name = "test", about = "Build and run tests using a Wasm interpreter.")]
    Test {
        #[structopt(
            raw = true,
            help = "Extra arguments passed to `cargo build` when building the test Wasm module."
        )]
        args: Vec<String>,
    },
    #[structopt(name = "build", about = "Build a deployment ready smart-contract module.")]
    Build {
        #[structopt(
            name = "schema-embed",
            long = "schema-embed",
            short = "e",
            help = "Builds the contract schema and embeds it into the wasm module."
        )]
        schema_embed: bool,
        #[structopt(
            name = "schema-output",
            long = "schema-output",
            short = "s",
            help = "Builds the contract schema and writes it to file at specified location."
        )]
        schema_output: Option<PathBuf>,
    },
}

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "runner")]
struct Runner {
    #[structopt(name = "source", long = "source", help = "Binary module source.")]
    source: PathBuf,
    #[structopt(
        name = "out-bin",
        long = "out-bin",
        help = "Where to write the new contract state to in binary format."
    )]
    out_bin: Option<PathBuf>,
    #[structopt(
        name = "out-json",
        long = "out-json",
        help = "Where to write the new contract state to in JSON format."
    )]
    out_json: Option<PathBuf>,
    #[structopt(
        name = "ignore-state-schema",
        long = "ignore-state-schema",
        help = "Disable displaying the state as JSON when a schema for the state is present."
    )]
    ignore_state_schema: bool,
    #[structopt(
        name = "amount",
        long = "amount",
        help = "The amount of micro GTU to invoke the method with.",
        default_value = "0"
    )]
    amount: u64,
    #[structopt(
        name = "schema",
        long = "schema",
        help = "Path to a file with a schema for parsing parameter or state in JSON"
    )]
    schema_path: Option<PathBuf>,
    #[structopt(
        name = "parameter-bin",
        long = "parameter-bin",
        help = "Path to a binary file with a parameter to invoke the method with. Parameter \
                defaults to an empty array if this is not given."
    )]
    parameter_bin_path: Option<PathBuf>,
    #[structopt(
        name = "parameter-json",
        long = "parameter-json",
        help = "Path to a JSON file with a parameter to invoke the method with. The JSON is \
                parsed using a schema, requiring the module to have an appropriate schema \
                embedded or otherwise provided by --schema."
    )]
    parameter_json_path: Option<PathBuf>,
    #[structopt(
        name = "energy",
        long = "energy",
        help = "Initial amount of energy to invoke the contract call with.",
        default_value = "1000000"
    )]
    energy: u64,
}

#[derive(Debug, StructOpt, Clone)]
enum RunCommand {
    #[structopt(name = "init", about = "Initialize a module.")]
    Init {
        #[structopt(
            name = "contract",
            long = "contract",
            short = "c",
            help = "Name of the contract to instantiate."
        )]
        contract_name: String,
        #[structopt(
            name = "context",
            long = "context",
            short = "t",
            default_value = "./init-context.json",
            help = "Path to the init context file."
        )]
        context: PathBuf,
        #[structopt(flatten)]
        runner: Runner,
    },
    #[structopt(name = "receive", about = "Invoke a receive method of a module.")]
    Receive {
        #[structopt(
            name = "contract",
            long = "contract",
            short = "c",
            help = "Name of the contract to receive message."
        )]
        contract_name: String,
        #[structopt(
            name = "function",
            long = "func",
            short = "f",
            help = "Name of the receive-function to receive message."
        )]
        func: String,

        #[structopt(
            name = "state-json",
            long = "state-json",
            help = "File with existing state of the contract in JSON, requires a schema is \
                    present either embedded or using --schema."
        )]
        state_json_path: Option<PathBuf>,
        #[structopt(
            name = "state-bin",
            long = "state-bin",
            help = "File with existing state of the contract in binary."
        )]
        state_bin_path: Option<PathBuf>,
        #[structopt(
            name = "balance",
            long = "balance",
            help = "Balance on the contract at the time it is invoked. Overrides the balance in \
                    the receive context."
        )]
        balance: Option<u64>,
        #[structopt(
            name = "context",
            long = "context",
            short = "t",
            help = "Path to the receive context file."
        )]
        context: PathBuf,
        #[structopt(flatten)]
        runner: Runner,
    },
}

pub fn main() {
    #[cfg(target_os = "windows")]
    {
        ansi_term::enable_ansi_support();
    }
    let cmd = {
        let app = CargoCommand::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::TrailingVarArg)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        let CargoCommand::Concordium(cmd) = CargoCommand::from_clap(&matches);
        cmd
    };
    match cmd {
        Command::Run(run_cmd) => {
            let (contract_name, runner) = match run_cmd.clone() {
                RunCommand::Init {
                    runner,
                    contract_name,
                    ..
                } => (contract_name, runner),
                RunCommand::Receive {
                    runner,
                    contract_name,
                    ..
                } => (contract_name, runner),
            };

            if runner.parameter_bin_path.is_some() && runner.parameter_json_path.is_some() {
                println!("Error: Only one parameter is allowed.");
                exit(1);
            }

            let source = fs::read(&runner.source).expect("Could not read module file.");

            let module_schema_opt = if let Some(schema_path) = &runner.schema_path {
                let bytes = fs::read(schema_path).expect("Failed reading schema file");
                let schema = from_bytes(&bytes).expect("Failed to parse schema file");
                Some(schema)
            } else {
                get_embedded_schema(&source).ok()
            };

            let contract_schema_opt = module_schema_opt
                .as_ref()
                .and_then(|module_schema| module_schema.contracts.get(&contract_name));
            let contract_schema_state_opt =
                contract_schema_opt.and_then(|contract_schema| contract_schema.state.clone());
            let contract_schema_func_opt =
                contract_schema_opt.and_then(|contract_schema| match run_cmd.clone() {
                    RunCommand::Init {
                        ..
                    } => contract_schema.init.as_ref(),
                    RunCommand::Receive {
                        func,
                        ..
                    } => contract_schema.receive.get(&func),
                });

            let print_result = |state: State, logs: Logs| {
                for (i, item) in logs.iterate().enumerate() {
                    println!("{}: {:#?}", i, item)
                }
                let state = &state.state;
                let output = match (runner.ignore_state_schema, &contract_schema_state_opt) {
                    (false, Some(state_schema)) => {
                        let s = state_schema
                            .to_json_string_pretty(&state)
                            .expect("Deserializing using state schema failed");
                        if runner.schema_path.is_some() {
                            format!("(Using provided schema)\n{}", s)
                        } else {
                            format!("(Using embedded schema)\n{}", s)
                        }
                    }
                    _ => format!("(No schema found for contract state)\n{:?}", state),
                };
                println!("The new state is: {}\n", output);

                if let Some(file_path) = &runner.out_bin {
                    let mut out_file =
                        File::create(file_path).expect("Could not create output file.");
                    out_file.write_all(&state).expect("Could not write out the state.")
                }
                if let Some(file_path) = &runner.out_json {
                    contract_schema_opt.expect(
                        "Schema is required for outputting state in JSON. No schema found for \
                         this contract.",
                    );
                    let schema_state = contract_schema_state_opt.as_ref().expect(
                        "Schema is required for outputting state in JSON. No schema found the \
                         state in this contract.",
                    );
                    let json_string = schema_state
                        .to_json_string_pretty(&state)
                        .expect("Failed encoding state to JSON.");
                    fs::write(file_path, json_string).expect("Could not write out the state.");
                }
            };

            let parameter = if let Some(param_file) = &runner.parameter_bin_path {
                fs::read(&param_file).expect("Could read parameter file.")
            } else if let Some(param_file) = &runner.parameter_json_path {
                // Find the right schema type
                if contract_schema_opt.is_none() {
                    println!(
                        "Error: No schema found for contract, the schema is required for \
                         inputting JSON."
                    );
                    exit(1);
                }
                let parameter_schema = contract_schema_func_opt
                    .expect("Contract schema did not contain a schema for this parameter.");

                let file = fs::read(&param_file).expect("Could read parameter file.");
                let parameter_json: serde_json::Value =
                    serde_json::from_slice(&file).expect("Failed parsing json");
                let mut parameter_bytes = Vec::new();
                write_bytes_from_json_schema_type(
                    &parameter_schema,
                    &parameter_json,
                    &mut parameter_bytes,
                )
                .expect("Failed parsing bytes");
                parameter_bytes
            } else {
                Vec::new()
            };

            match run_cmd {
                RunCommand::Init {
                    ref contract_name,
                    ref context,
                    ..
                } => {
                    let init_ctx = {
                        let ctx_file = File::open(context).expect("Could not open context file.");
                        serde_json::from_reader(std::io::BufReader::new(ctx_file))
                            .expect("Could not parse init context")
                    };
                    let name = format!("init_{}", contract_name);
                    let res = invoke_init_with_metering_from_source(
                        &source,
                        runner.amount,
                        init_ctx,
                        &name,
                        parameter,
                        runner.energy,
                    )
                    .expect("Invocation failed.");
                    match res {
                        InitResult::Success {
                            logs,
                            state,
                            remaining_energy,
                        } => {
                            println!("Init call succeeded. The following logs were produced.");
                            print_result(state, logs);
                            println!("Remaining energy is {}", remaining_energy)
                        }
                        InitResult::Reject {
                            remaining_energy,
                        } => {
                            println!("Init call rejected.");
                            println!("Remaining energy is {}", remaining_energy)
                        }
                        InitResult::OutOfEnergy => {
                            println!("Init call terminated with out of energy.")
                        }
                    };
                }
                RunCommand::Receive {
                    ref contract_name,
                    ref func,
                    ref state_bin_path,
                    ref state_json_path,
                    balance,
                    ref context,
                    ..
                } => {
                    let mut receive_ctx: contracts_common::ReceiveContext = {
                        let ctx_file = File::open(context).expect("Could not open context file.");
                        serde_json::from_reader(std::io::BufReader::new(ctx_file))
                            .expect("Could not parse receive context")
                    };
                    if let Some(balance) = balance {
                        receive_ctx.self_balance =
                            contracts_common::Amount::from_micro_gtu(balance);
                    }

                    // initial state of the smart contract, read from either a binary or json file.
                    let init_state = match (state_bin_path, state_json_path) {
                        (None, None) => panic!(
                            "The current state is required for simulating an update to a contract \
                             instance. Use either --state-bin or --state-json."
                        ),
                        (Some(_), Some(_)) => panic!(
                            "Only one state is allowed, choose either --state-bin or --state-json."
                        ),
                        (Some(file_path), None) => {
                            let mut file =
                                File::open(&file_path).expect("Could not read state file.");
                            let metadata = file.metadata().expect("Could not read file metadata.");
                            let mut init_state = Vec::with_capacity(metadata.len() as usize);
                            file.read_to_end(&mut init_state)
                                .expect("Reading the state file failed.");
                            init_state
                        }
                        (None, Some(file_path)) => {
                            let schema_state = contract_schema_state_opt
                                .as_ref()
                                .expect("A schema for the state must be present to use JSON.");
                            let file = fs::read(&file_path).expect("Could read parameter file.");
                            let state_json: serde_json::Value =
                                serde_json::from_slice(&file).expect("Failed parsing json");
                            let mut state_bytes = Vec::new();
                            write_bytes_from_json_schema_type(
                                &schema_state,
                                &state_json,
                                &mut state_bytes,
                            )
                            .expect("Failed parsing bytes");
                            state_bytes
                        }
                    };

                    let name = format!("{}.{}", contract_name, func);
                    let res = invoke_receive_with_metering_from_source(
                        &source,
                        runner.amount,
                        receive_ctx,
                        &init_state,
                        &name,
                        parameter,
                        runner.energy,
                    )
                    .expect("Calling receive failed.");
                    match res {
                        ReceiveResult::Success {
                            logs,
                            state,
                            actions,
                            remaining_energy,
                        } => {
                            println!("Receive method succeeded. The following logs were produced.");
                            print_result(state, logs);
                            println!("The following actions were produced.");
                            for (i, action) in actions.iter().enumerate() {
                                match action {
                                    Action::Send {
                                        to_addr,
                                        name,
                                        amount,
                                        parameter,
                                    } => {
                                        // Contract validation ensures that names are valid
                                        // ascii sequences, so unwrap is OK.
                                        let name_str = std::str::from_utf8(name).unwrap();
                                        println!(
                                            "{}: send a message to contract at ({}, {}), calling \
                                             method {} with amount {} and parameter {:?}",
                                            i,
                                            to_addr.index,
                                            to_addr.subindex,
                                            name_str,
                                            amount,
                                            parameter
                                        )
                                    }
                                    Action::SimpleTransfer {
                                        to_addr,
                                        amount,
                                    } => {
                                        println!(
                                            "{}: simple transfer to account {} of amount {}",
                                            i,
                                            serde_json::to_string(to_addr).expect(
                                                "Address not valid JSON, should not happen."
                                            ),
                                            amount
                                        );
                                    }
                                    Action::And {
                                        l,
                                        r,
                                    } => println!("{}: AND composition of {} and {}", i, l, r),
                                    Action::Or {
                                        l,
                                        r,
                                    } => println!("{}: OR composition of {} and {}", i, l, r),
                                    Action::Accept => println!("{}: ACCEPT", i),
                                }
                            }

                            println!("Remaining energy is {}.", remaining_energy)
                        }
                        ReceiveResult::Reject {
                            remaining_energy,
                        } => {
                            println!("Receive call rejected.");
                            println!("Remaining energy is {}.", remaining_energy)
                        }
                        ReceiveResult::OutOfEnergy => {
                            println!("Receive call terminated with: out of energy.")
                        }
                    }
                }
            }
        }
        Command::Test {
            args,
        } => {
            let res = build_and_run_wasm_test(&args);
            match res {
                Ok(true) => {}
                Ok(false) => std::process::exit(1),
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1)
                }
            }
        }
        Command::Build {
            schema_embed,
            schema_output,
        } => {
            let build_schema = schema_embed || schema_output.is_some();
            let schema_to_embed = if build_schema {
                let module_schema = match build_contract_schema() {
                    Ok(schema) => schema,
                    Err(err) => {
                        eprintln!("Failed building schema {}", err);
                        panic!()
                    }
                };

                for (contract_name, contract_schema) in module_schema.contracts.iter() {
                    print_contract_schema(contract_name, contract_schema);
                }
                let module_schema_bytes = to_bytes(&module_schema);
                eprintln!(
                    "Total size of the module schema is: {} bytes",
                    module_schema_bytes.len()
                );

                if let Some(schema_out) = schema_output {
                    eprintln!("Writing schema to {}.", schema_out.to_string_lossy());
                    fs::write(schema_out, &module_schema_bytes).unwrap();
                }
                if schema_embed {
                    eprintln!("Embedding schema into contract module.");
                    Some(module_schema)
                } else {
                    None
                }
            } else {
                None
            };
            let res = build_contract(schema_to_embed);
            match res {
                Ok(_) => eprintln!("\nDone building your smart contract."),
                Err(err) => eprintln!("\nFailed building your smart contract: {}", err),
            }
        }
    }
}

fn print_contract_schema(
    contract_name: &str,
    contract_schema: &contracts_common::schema::Contract,
) {
    println!("\n Schema for contract: {}\n", contract_name);
    let contract_schema_bytes = to_bytes(contract_schema);
    match &contract_schema.state {
        Some(state_schema) => {
            println!("Contract state: {}:\n{:#?}\n", contract_name, state_schema);
        }
        None => {
            println!(
                "No schema found for the contract state. Did you annotate the state data with \
                 `#[contract_state(...)]`?

#[contract_state(contract = \"my-contract\")]
struct State {{ ... }}
"
            );
        }
    }

    if contract_schema.receive.is_empty() {
        println!(
            "No schemas found for method parameters.

To include a schema for a method parameter specify the parameter type as an attribute to \
             `#[init(..)]` or `#[receive(..)]`
            #[init(..., parameter = \"MyParamType\")]     or     #[receive(..., parameter = \
             \"MyParamType\")]
"
        )
    } else {
        println!("Found schemas for the following methods:\n");
        for (method_name, param_type) in contract_schema.receive.iter() {
            println!("'{}': {:#?}\n", method_name, param_type);
        }
    }

    println!("Size of this contract schema is {} bytes.\n", contract_schema_bytes.len());
}
