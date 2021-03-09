use crate::{build::*, schema_json::*};
use anyhow::{bail, ensure, Context};
use clap::AppSettings;
use concordium_contracts_common::{from_bytes, to_bytes, Amount, OwnedPolicy};
use std::{fs, fs::File, io::Read, path::PathBuf};
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
            name = "schema-out",
            long = "schema-out",
            short = "s",
            help = "Builds the contract schema and writes it to file at specified location."
        )]
        schema_out: Option<PathBuf>,
        #[structopt(
            name = "out",
            long = "out",
            short = "o",
            help = "Writes the resulting module to file at specified location."
        )]
        out: Option<PathBuf>,
        #[structopt(
            raw = true,
            help = "Extra arguments passed to `cargo build` when building Wasm module."
        )]
        cargo_args: Vec<String>,
    },
}

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "runner")]
struct Runner {
    #[structopt(name = "module", long = "module", help = "Binary module source.")]
    module: PathBuf,
    #[structopt(
        name = "out-bin",
        long = "out-bin",
        help = "Where to write the new contract state to in binary format."
    )]
    out_bin: Option<PathBuf>,
    #[structopt(
        name = "out-json",
        long = "out-json",
        help = "Where to write the new contract state to in JSON format, requiring the module to \
                have an appropriate schema embedded or otherwise provided by --schema."
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
        help = "The amount of GTU to invoke the method with.",
        default_value = "0"
    )]
    amount: Amount,
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
    #[structopt(name = "update", about = "Invoke a receive method of a module.")]
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

pub fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        ansi_term::enable_ansi_support();
    }
    let success_style = ansi_term::Color::Green.bold();
    let warning_style = ansi_term::Color::Yellow;
    let bold_style = ansi_term::Style::new().bold();

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

            ensure!(
                !(runner.parameter_bin_path.is_some() && runner.parameter_json_path.is_some()),
                "Both --parameter-bin and --parameter-json are supplied. Only one parameter is \
                 allowed."
            );

            let module = fs::read(&runner.module).context("Could not read module file.")?;

            let module_schema_opt = if let Some(schema_path) = &runner.schema_path {
                let bytes = fs::read(schema_path).context("Could not read schema file.")?;
                let schema = from_bytes(&bytes)
                    .map_err(|_| anyhow::anyhow!("Could not deserialize schema file."))?;
                Some(schema)
            } else {
                let res = get_embedded_schema(&module);
                if let Err(err) = &res {
                    eprintln!(
                        "{}",
                        warning_style.paint(format!("Could not use embedded schema: {}", err))
                    );
                }
                res.ok()
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

            let print_result = |state: State, logs: Logs| -> anyhow::Result<()> {
                for (i, item) in logs.iterate().enumerate() {
                    eprintln!("{}: {:?}", i, item)
                }
                let state = &state.state;
                match (runner.ignore_state_schema, &contract_schema_state_opt) {
                    (false, Some(state_schema)) => {
                        let s = state_schema
                            .to_json_string_pretty(&state)
                            .map_err(|_| anyhow::anyhow!("Could not encode state to JSON."))?;
                        if runner.schema_path.is_some() {
                            eprintln!("The new state is: (Using provided schema)\n{}", s)
                        } else {
                            eprintln!("The new state is: (Using embedded schema)\n{}", s)
                        }
                    }
                    _ => eprintln!(
                        "The new state is: (No schema found for contract state) {:?}\n",
                        state
                    ),
                };

                if let Some(file_path) = &runner.out_bin {
                    fs::write(file_path, &state).context("Could not write state to file")?;
                }
                if let Some(file_path) = &runner.out_json {
                    contract_schema_opt.context(
                        "Schema is required for outputting state in JSON. No schema found for \
                         this contract.",
                    )?;
                    let schema_state = contract_schema_state_opt.as_ref().context(
                        "Schema is required for outputting state in JSON. No schema found the \
                         state in this contract.",
                    )?;
                    let json_string = schema_state
                        .to_json_string_pretty(&state)
                        .map_err(|_| anyhow::anyhow!("Could not output contract state in JSON."))?;
                    fs::write(file_path, json_string).context("Could not write out the state.")?;
                }
                Ok(())
            };

            let parameter = if let Some(param_file) = &runner.parameter_bin_path {
                fs::read(&param_file).context("Could not read parameter-bin file.")
            } else if let Some(param_file) = &runner.parameter_json_path {
                if contract_schema_opt.is_none() {
                    Err(anyhow::anyhow!(
                        "No schema found for contract, a schema is required for using \
                         --parameter-json."
                    ))
                } else {
                    let parameter_schema = contract_schema_func_opt
                        .context("Contract schema did not contain a schema for this parameter.")?;

                    let file = fs::read(&param_file).context("Could not read parameter file.")?;
                    let parameter_json: serde_json::Value = serde_json::from_slice(&file)
                        .context("Could not parse the JSON in parameter-json file.")?;
                    let mut parameter_bytes = Vec::new();
                    write_bytes_from_json_schema_type(
                        &parameter_schema,
                        &parameter_json,
                        &mut parameter_bytes,
                    )
                    .context("Could not generate parameter bytes using schema and JSON.")?;
                    Ok(parameter_bytes)
                }
            } else {
                Ok(Vec::new())
            }
            .context("Could not get parameter.")?;

            match run_cmd {
                RunCommand::Init {
                    ref contract_name,
                    ref context,
                    ..
                } => {
                    let init_ctx: InitContext = {
                        let ctx_file = fs::read(context).context("Could not open context file.")?;
                        serde_json::from_slice(&ctx_file)
                            .context("Could not parse the init context JSON.")?
                    };
                    let name = format!("init_{}", contract_name);
                    let res = invoke_init_with_metering_from_source(
                        &module,
                        runner.amount.micro_gtu,
                        init_ctx,
                        &name,
                        &parameter,
                        runner.energy,
                    )
                    .context("Invocation failed.")?;
                    match res {
                        InitResult::Success {
                            logs,
                            state,
                            remaining_energy,
                        } => {
                            eprintln!("Init call succeeded. The following logs were produced:");
                            print_result(state, logs)?;
                            eprintln!("Energy spent is {}", runner.energy - remaining_energy)
                        }
                        InitResult::Reject {
                            remaining_energy,
                        } => {
                            eprintln!("Init call rejected.");
                            eprintln!("Energy spent is {}", runner.energy - remaining_energy)
                        }
                        InitResult::OutOfEnergy => {
                            eprintln!("Init call terminated with out of energy.")
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
                    let mut receive_ctx: ReceiveContext<Vec<OwnedPolicy>> = {
                        let ctx_file = fs::read(context).context("Could not open context file.")?;
                        serde_json::from_slice::<ReceiveContext<Vec<OwnedPolicy>>>(&ctx_file)
                            .context("Could not parse receive context")?
                    };
                    if let Some(balance) = balance {
                        receive_ctx.self_balance =
                            concordium_contracts_common::Amount::from_micro_gtu(balance);
                    }

                    // initial state of the smart contract, read from either a binary or json file.
                    let init_state = match (state_bin_path, state_json_path) {
                        (None, None) => bail!(
                            "The current state is required for simulating an update to a contract \
                             instance. Use either --state-bin or --state-json."
                        ),
                        (Some(_), Some(_)) => bail!(
                            "Only one state is allowed, choose either --state-bin or --state-json."
                        ),
                        (Some(file_path), None) => {
                            let mut file =
                                File::open(&file_path).context("Could not read state file.")?;
                            let metadata =
                                file.metadata().context("Could not read file metadata.")?;
                            let mut init_state = Vec::with_capacity(metadata.len() as usize);
                            file.read_to_end(&mut init_state)
                                .context("Reading the state file failed.")?;
                            init_state
                        }
                        (None, Some(file_path)) => {
                            let schema_state = contract_schema_state_opt
                                .as_ref()
                                .context("A schema for the state must be present to use JSON.")?;
                            let file =
                                fs::read(&file_path).context("Could not read state file.")?;
                            let state_json: serde_json::Value = serde_json::from_slice(&file)
                                .context("Could not parse state JSON.")?;
                            let mut state_bytes = Vec::new();
                            write_bytes_from_json_schema_type(
                                &schema_state,
                                &state_json,
                                &mut state_bytes,
                            )
                            .context("Could not generate state bytes using schema and JSON.")?;
                            state_bytes
                        }
                    };

                    let name = format!("{}.{}", contract_name, func);
                    let res = invoke_receive_with_metering_from_source(
                        &module,
                        runner.amount.micro_gtu,
                        receive_ctx,
                        &init_state,
                        &name,
                        &parameter,
                        runner.energy,
                    )
                    .context("Calling receive failed.")?;
                    match res {
                        ReceiveResult::Success {
                            logs,
                            state,
                            actions,
                            remaining_energy,
                        } => {
                            eprintln!(
                                "Receive method succeeded. The following logs were produced."
                            );
                            print_result(state, logs)?;
                            eprintln!("The following actions were produced.");
                            for (i, action) in actions.iter().enumerate() {
                                match action {
                                    Action::Send {
                                        data,
                                    } => {
                                        let name_str = std::str::from_utf8(&data.name)
                                            .context("Target name is not a valid UTF8 sequence.")?;
                                        eprintln!(
                                            "{}: send a message to contract at ({}, {}), calling \
                                             method {} with amount {} and parameter {:?}",
                                            i,
                                            data.to_addr.index,
                                            data.to_addr.subindex,
                                            name_str,
                                            data.amount,
                                            parameter
                                        )
                                    }
                                    Action::SimpleTransfer {
                                        data,
                                    } => {
                                        eprintln!(
                                            "{}: simple transfer to account {} of amount {}",
                                            i,
                                            serde_json::to_string(&data.to_addr).context(
                                                "Address not valid JSON, should not happen."
                                            )?,
                                            data.amount
                                        );
                                    }
                                    Action::And {
                                        l,
                                        r,
                                    } => eprintln!("{}: AND composition of {} and {}", i, l, r),
                                    Action::Or {
                                        l,
                                        r,
                                    } => eprintln!("{}: OR composition of {} and {}", i, l, r),
                                    Action::Accept => eprintln!("{}: ACCEPT", i),
                                }
                            }

                            eprintln!("Energy spent is {}", runner.energy - remaining_energy)
                        }
                        ReceiveResult::Reject {
                            remaining_energy,
                        } => {
                            eprintln!("Receive call rejected.");
                            eprintln!("Energy spent is {}", runner.energy - remaining_energy)
                        }
                        ReceiveResult::OutOfEnergy => {
                            eprintln!("Receive call terminated with: out of energy.")
                        }
                    }
                }
            }
        }
        Command::Test {
            args,
        } => {
            let success =
                build_and_run_wasm_test(&args).context("Could not build and run tests.")?;
            ensure!(success, "Test failed");
        }
        Command::Build {
            schema_embed,
            schema_out,
            out,
            cargo_args,
        } => {
            let build_schema = schema_embed || schema_out.is_some();
            let schema_opt = if build_schema {
                let schema =
                    build_contract_schema(&cargo_args).context("Could not build module schema.")?;
                Some(schema)
            } else {
                None
            };
            let byte_len = if schema_embed {
                build_contract(&schema_opt, out, &cargo_args)
            } else {
                build_contract(&None, out, &cargo_args)
            }
            .context("Could not build smart contract.")?;
            if let Some(module_schema) = &schema_opt {
                eprintln!("\n   Module schema includes:");
                for (contract_name, contract_schema) in module_schema.contracts.iter() {
                    print_contract_schema(&contract_name, &contract_schema);
                }
                let module_schema_bytes = to_bytes(module_schema);
                eprintln!(
                    "\n   Total size of the module schema is {} {}",
                    bold_style.paint(module_schema_bytes.len().to_string()),
                    bold_style.paint("B")
                );

                if let Some(schema_out) = schema_out {
                    eprintln!("   Writing schema to {}.", schema_out.to_string_lossy());
                    fs::write(schema_out, &module_schema_bytes)
                        .context("Could not write schema file.")?;
                }
                if schema_embed {
                    eprintln!("   Embedding schema into module.\n");
                }
            }
            let size = format!("{}.{:03} kB", byte_len / 1000, byte_len % 1000);
            eprintln!(
                "    {} smart contract module {}",
                success_style.paint("Finished"),
                bold_style.paint(size)
            )
        }
    };
    Ok(())
}

fn print_contract_schema(
    contract_name: &str,
    contract_schema: &concordium_contracts_common::schema::Contract,
) {
    let max_length_receive_opt =
        contract_schema.receive.iter().map(|(n, _)| n.chars().count()).max();
    let colon_position = max_length_receive_opt.map(|m| m.max(5)).unwrap_or(5);
    eprintln!(
        "\n     Contract schema: '{}' in total {} B.",
        contract_name,
        to_bytes(contract_schema).len()
    );
    if let Some(state_schema) = &contract_schema.state {
        eprintln!("       state   : {} B", to_bytes(state_schema).len());
    }
    if let Some(init_schema) = &contract_schema.init {
        eprintln!("       init    : {} B", to_bytes(init_schema).len())
    }

    if !contract_schema.receive.is_empty() {
        eprintln!("       receive");
        for (method_name, param_type) in contract_schema.receive.iter() {
            eprintln!(
                "        - {:width$} : {} B",
                format!("'{}'", method_name),
                to_bytes(param_type).len(),
                width = colon_position + 2
            );
        }
    }
}
