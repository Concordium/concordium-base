use crate::build::*;
use clap::AppSettings;
use contracts_common::to_bytes;
use std::{
    fs::{read, write, File},
    io::{Read, Write},
    path::PathBuf,
};
use structopt::StructOpt;
use wasmer_interp::*;

mod build;

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

    #[structopt(name = "test", about = "Run tests using the Wasm interpreter.")]
    Test {
        #[structopt(
            name = "source",
            long = "source",
            default_value = "contract.wasm",
            help = "Binary module source."
        )]
        source: PathBuf,
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
    #[structopt(
        name = "source",
        long = "source",
        // default_value = "contract.wasm",
        help = "Binary module source."
    )]
    source: PathBuf,
    #[structopt(
        name = "out",
        long = "out",
        help = "Where to write the new contract state to. Defaults to stdout if not given."
    )]
    out: Option<PathBuf>,
    #[structopt(
        name = "hex",
        long = "hex",
        help = "Whether to write the state as a hex string or not. Defaults to binary."
    )]
    hex_state: bool,
    #[structopt(
        name = "amount",
        long = "amount",
        help = "The amount of micro GTU to invoke the method with.",
        default_value = "0"
    )]
    amount: u64,
    #[structopt(
        name = "parameter",
        long = "parameter",
        help = "Path to a file with a parameter to invoke the method with. Parameter defaults to \
                an empty array if this is not given."
    )]
    parameter: Option<PathBuf>,
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
            name = "name",
            long = "name",
            help = "Name of the method to invoke.",
            default_value = "init"
        )]
        name: String,
        #[structopt(
            name = "context",
            long = "context",
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
            name = "name",
            long = "name",
            help = "Name of the method to invoke.",
            default_value = "receive"
        )]
        name: String,
        #[structopt(
            name = "state",
            long = "state",
            help = "File with existing state of the contract."
        )]
        state: PathBuf,
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
            default_value = "./receive-context.json",
            help = "Path to the receive context file."
        )]
        context: PathBuf,
        #[structopt(flatten)]
        runner: Runner,
    },
}

pub fn main() {
    let cmd = {
        let app = CargoCommand::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        let CargoCommand::Concordium(cmd) = CargoCommand::from_clap(&matches);
        cmd
    };
    match cmd {
        Command::Run(run_cmd) => {
            let runner = match run_cmd.clone() {
                RunCommand::Init {
                    runner,
                    ..
                } => runner,
                RunCommand::Receive {
                    runner,
                    ..
                } => runner,
            };
            println!("runner {:?}", runner.source);
            let source = read(&runner.source).expect("Could not read file.");

            let print_result = |state: State, logs: Logs| {
                for (i, item) in logs.iterate().iter().enumerate() {
                    if let Ok(s) = std::str::from_utf8(item) {
                        println!("{}: {}", i, s)
                    } else {
                        println!("{}: {:?}", i, item)
                    }
                }
                let state = state.get();
                if runner.hex_state {
                    let output = hex::encode(&state);
                    match &runner.out {
                        None => println!("The new state is: {}", output),
                        Some(fp) => {
                            let mut out_file =
                                File::create(fp).expect("Could not create output file.");
                            out_file
                                .write_all(output.as_bytes())
                                .expect("Could not write out the state.");
                        }
                    }
                } else {
                    let output = match get_embedded_schema(&source) {
                        Ok(contract_schema) => match contract_schema.state {
                            Some(state_schema) => {
                                let s = state_schema
                                    .to_json_string_pretty(&state)
                                    .expect("Deserializing using state schema failed");
                                format!("(Using embedded schema)\n{}", s)
                            }
                            None => format!("(No schema found for contract state)\n{:?}", state),
                        },
                        Err(err) => format!("(Failed to get schema: {})\n{:?}", err, state),
                    };
                    match &runner.out {
                        None => println!("The new state is: {}\n", output),
                        Some(fp) => {
                            let mut out_file =
                                File::create(fp).expect("Could not create output file.");
                            out_file.write_all(&state).expect("Could not write out the state.")
                        }
                    }
                }
            };

            let parameter = match &runner.parameter {
                None => Vec::new(),
                Some(param_file) => {
                    let mut param_file =
                        File::open(&param_file).expect("Could not open parameter file.");
                    let mut input = Vec::new();
                    param_file
                        .read_to_end(&mut input)
                        .expect("Could not read from parameter file.");
                    input
                }
            };

            match run_cmd {
                RunCommand::Init {
                    ref name,
                    ref context,
                    ..
                } => {
                    let init_ctx = {
                        let ctx_file = File::open(context).expect("Could not open context file.");
                        serde_json::from_reader(std::io::BufReader::new(ctx_file))
                            .expect("Could not parse init context")
                    };
                    let res = invoke_init(
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
                    ref name,
                    ref state,
                    balance,
                    ref context,
                    ..
                } => {
                    let mut receive_ctx: contracts_common::ReceiveContext = {
                        let ctx_file = File::open(context).expect("Could not open context file.");
                        serde_json::from_reader(std::io::BufReader::new(ctx_file))
                            .expect("Could not parse init context")
                    };
                    if let Some(balance) = balance {
                        receive_ctx.self_balance =
                            contracts_common::Amount::from_micro_gtu(balance);
                    }

                    // initial state of the smart contract, read from a file.
                    let init_state = {
                        let mut file = File::open(&state).expect("Could not read state file.");
                        let metadata = file.metadata().expect("Could not read file metadata.");
                        let mut init_state = Vec::with_capacity(metadata.len() as usize);
                        file.read_to_end(&mut init_state).expect("Reading the state file failed.");
                        init_state
                    };
                    let res = invoke_receive(
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
                                    } => println!(
                                        "{}: send a message to contract at ({}, {}), calling \
                                         method {:?} with amount {} and parameter {:?}",
                                        i, to_addr.index, to_addr.subindex, name, amount, parameter
                                    ),
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
                            println!("Receive call terminated with out of energy.")
                        }
                    }
                }
            }
        }
        Command::Test {
            source,
        } => {
            let source = read(&source).expect("Could not read file.");
            test_run(&source).expect("Invocation failed.");
        }
        Command::Build {
            schema_embed,
            schema_output,
        } => {
            let build_schema = schema_embed || schema_output.is_some();
            if build_schema {
                let contract_schema = match build_contract_schema() {
                    Ok(schema) => schema,
                    Err(err) => {
                        println!("{}", err);
                        panic!()
                    }
                };
                let contract_schema_bytes = to_bytes(&contract_schema);
                match contract_schema.state {
                    Some(state_schema) => {
                        println!("Found schema for the contract state:\n\n{:#?}\n", state_schema);
                    }
                    None => {
                        println!(
                            "No schema found for the contract state. Did you annotate the state \
                             data with `#[contract_state(...)]`?

        #[contract_state(contract = \"my-contract\")]
        struct State {{ ... }}
    "
                        );
                    }
                }

                if contract_schema.method_parameter.is_empty() {
                    println!(
                        "No schemas found for method parameters.
To include a schema for a method parameter specify the parameter type as an attribute to \
                         `#[init(..)]` or `#[receive(..)]`
        #[init(..., parameter = \"MyParamType\")]     or     #[receive(..., parameter = \
                         \"MyParamType\")]"
                    )
                } else {
                    println!("Found schemas for the following methods:\n");
                    for (method_name, param_type) in contract_schema.method_parameter.iter() {
                        println!("'{}': {:#?}\n", method_name, param_type);
                    }
                }
                println!(
                    "\nTotal size of contract schema is {} bytes.\n",
                    contract_schema_bytes.len()
                );
                match schema_output {
                    None => {}
                    Some(schema_out) => {
                        println!("Writing schema to {:?}.", schema_out);
                        write(schema_out, &contract_schema_bytes).unwrap();
                    }
                }
                if schema_embed {
                    println!("Embedding schema into contract module.");
                    todo!("Embed the schema as a custom section in the wasm module");
                }
            }
            // TODO: Actually build the contract without the code for schema generation.
            println!("\nDone building your smart contract.");
        }
    }
}
