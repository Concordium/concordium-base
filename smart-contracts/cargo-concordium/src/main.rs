use crate::{
    build::*,
    context::{InitContextOpt, ReceiveContextOpt},
    schema_json::write_bytes_from_json_schema_type,
};
use anyhow::{bail, ensure, Context};
use clap::AppSettings;
use concordium_contracts_common::{
    from_bytes,
    schema::{FunctionSchema, Type},
    to_bytes, Amount, Parameter,
};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};
use structopt::StructOpt;
use wasm_chain_integration::{
    utils, v0,
    v1::{self, ReturnValue},
};

mod build;
mod context;
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
        schema_out:   Option<PathBuf>,
        #[structopt(
            name = "out",
            long = "out",
            short = "o",
            help = "Writes the resulting module to file at specified location."
        )]
        out:          Option<PathBuf>,
        #[structopt(
            name = "version",
            long = "version",
            short = "v",
            help = "Build a module of the given version.",
            default_value = "V1"
        )]
        version:      utils::WasmVersion,
        #[structopt(
            raw = true,
            help = "Extra arguments passed to `cargo build` when building Wasm module."
        )]
        cargo_args:   Vec<String>,
    },
}

#[derive(Debug, StructOpt)]
#[structopt(name = "runner")]
struct Runner {
    #[structopt(name = "module", long = "module", help = "Binary module source.")]
    module:              PathBuf,
    #[structopt(
        name = "out-bin",
        long = "out-bin",
        help = "Where to write the new contract state to in binary format."
    )]
    out_bin:             Option<PathBuf>,
    #[structopt(
        name = "out-json",
        long = "out-json",
        help = "Where to write the new contract state to in JSON format, requiring the module to \
                have an appropriate schema embedded or otherwise provided by --schema. This only \
                applies to V0 contracts."
    )]
    out_json:            Option<PathBuf>,
    #[structopt(
        name = "ignore-state-schema",
        long = "ignore-state-schema",
        help = "Disable displaying the state as JSON when a schema for the state is present. This \
                only applies to V0 contracts."
    )]
    ignore_state_schema: bool,
    #[structopt(
        name = "amount",
        long = "amount",
        help = "The amount of CCD to invoke the method with.",
        default_value = "0"
    )]
    amount:              Amount,
    #[structopt(
        name = "schema",
        long = "schema",
        help = "Path to a file with a schema for parsing parameter or state (only for V0 \
                contracts) in JSON."
    )]
    schema_path:         Option<PathBuf>,
    #[structopt(
        name = "parameter-bin",
        long = "parameter-bin",
        conflicts_with = "parameter-json",
        help = "Path to a binary file with a parameter to invoke the method with. Parameter \
                defaults to an empty array if this is not given."
    )]
    parameter_bin_path:  Option<PathBuf>,
    #[structopt(
        name = "parameter-json",
        long = "parameter-json",
        conflicts_with = "parameter-bin",
        help = "Path to a JSON file with a parameter to invoke the method with. The JSON is \
                parsed using a schema, requiring the module to have an appropriate schema \
                embedded or otherwise provided by --schema."
    )]
    parameter_json_path: Option<PathBuf>,
    #[structopt(
        name = "energy",
        long = "energy",
        help = "Initial amount of interpreter energy to invoke the contract call with. Note that \
                interpreter energy is not the same as NRG, there is a conversion factor between \
                them.",
        default_value = "1000000"
    )]
    energy:              u64,
}

#[derive(Debug, StructOpt)]
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
            help = "Path to the init context file."
        )]
        context:       Option<PathBuf>,
        #[structopt(flatten)]
        runner:        Runner,
    },
    #[structopt(
        name = "update",
        about = "Invoke a receive method of a
module."
    )]
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
        func:          String,

        #[structopt(
            name = "state-json",
            long = "state-json",
            help = "File with existing state of the contract in JSON,
requires a schema is present either embedded or using
--schema."
        )]
        state_json_path: Option<PathBuf>,
        #[structopt(
            name = "state-bin",
            long = "state-bin",
            help = "File with existing state of the contract in binary."
        )]
        state_bin_path:  Option<PathBuf>,
        #[structopt(
            name = "balance",
            long = "balance",
            help = "Balance on the contract at the time it is invoked.
Overrides the balance in the receive context."
        )]
        balance:         Option<u64>,
        #[structopt(
            name = "context",
            long = "context",
            short = "t",
            help = "Path to the receive context file."
        )]
        context:         Option<PathBuf>,
        #[structopt(flatten)]
        runner:          Runner,
    },
}

const WARNING_STYLE: ansi_term::Color = ansi_term::Color::Yellow;

pub fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        ansi_term::enable_ansi_support();
    }
    let success_style = ansi_term::Color::Green.bold();
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
            let runner = match run_cmd {
                RunCommand::Init {
                    ref runner,
                    ..
                } => runner,
                RunCommand::Receive {
                    ref runner,
                    ..
                } => runner,
            };
            // Expect a versioned module. The first 4 bytes are the WasmVersion.
            let versioned_module =
                fs::read(&runner.module).context("Could not read module file.")?;
            let mut cursor = std::io::Cursor::new(&versioned_module[..]);
            let wasm_version = utils::WasmVersion::read(&mut cursor)
                .context("Could not read module version from the supplied module file.")?;

            let len = {
                let mut buf = [0u8; 4];
                cursor.read_exact(&mut buf).context("Could not parse supplied module.")?;
                u32::from_be_bytes(buf)
            };
            let module = &cursor.into_inner()[8..];
            ensure!(
                module.len() == len as usize,
                "Could no parse the supplied module. The specified length does not match the size \
                 of the provided data."
            );
            match wasm_version {
                utils::WasmVersion::V0 => handle_run_v0(run_cmd, module)?,
                utils::WasmVersion::V1 => handle_run_v1(run_cmd, module)?,
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
            version,
            cargo_args,
        } => {
            let build_schema = if schema_embed {
                Some(true)
            } else if schema_out.is_some() {
                Some(false)
            } else {
                None
            };
            let (byte_len, schema) = build_contract(version, build_schema, out, &cargo_args)
                .context("Could not build smart contract.")?;
            if let Some(module_schema) = &schema {
                let module_schema_bytes = match module_schema {
                    ModuleSchema::V0(module_schema) => {
                        eprintln!("\n   Module schema includes:");
                        for (contract_name, contract_schema) in module_schema.contracts.iter() {
                            print_contract_schema_v0(&contract_name, &contract_schema);
                        }
                        to_bytes(module_schema)
                    }
                    ModuleSchema::V1(module_schema) => {
                        eprintln!("\n   Module schema includes:");
                        for (contract_name, contract_schema) in module_schema.contracts.iter() {
                            print_contract_schema_v1(&contract_name, &contract_schema);
                        }
                        to_bytes(module_schema)
                    }
                };
                eprintln!(
                    "\n   Total size of the module schema is {} {}",
                    bold_style.paint(module_schema_bytes.len().to_string()),
                    bold_style.paint("B")
                );

                if let Some(schema_out) = schema_out {
                    eprintln!("   Writing schema to {}.", schema_out.display());
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

/// Print the contract name and its entrypoints
fn print_schema_info(contract_name: &str, len: usize) {
    eprintln!("\n     Contract schema: '{}' in total {} B.", contract_name, len,);
}

/// Based on the list of receive names compute the colon position for aligning
/// prints.
fn get_colon_position<'a>(iter: impl Iterator<Item = &'a str>) -> usize {
    let max_length_receive_opt = iter.map(|n| n.chars().count()).max();
    max_length_receive_opt.map_or(5, |m| m.max(5))
}

fn print_contract_schema_v0(
    contract_name: &str,
    contract_schema: &concordium_contracts_common::schema::ContractV0,
) {
    let receive_iter = contract_schema.receive.iter().map(|(n, _)| n.as_str());
    let colon_position = get_colon_position(receive_iter);

    print_schema_info(contract_name, to_bytes(contract_schema).len());

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

fn print_contract_schema_v1(
    contract_name: &str,
    contract_schema: &concordium_contracts_common::schema::ContractV1,
) {
    let receive_iter = contract_schema.receive.iter().map(|(n, _)| n.as_str());
    let colon_position = get_colon_position(receive_iter);

    print_schema_info(contract_name, to_bytes(contract_schema).len());

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

fn handle_run_v0(run_cmd: RunCommand, module: &[u8]) -> anyhow::Result<()> {
    let (contract_name, runner, is_receive) = match run_cmd {
        RunCommand::Init {
            ref runner,
            ref contract_name,
            ..
        } => (contract_name, runner, None),
        RunCommand::Receive {
            ref runner,
            ref contract_name,
            ref func,
            ..
        } => (contract_name, runner, Some(func)),
    };

    // get the module schema if available.
    let module_schema_opt = if let Some(schema_path) = &runner.schema_path {
        let bytes = fs::read(schema_path).context("Could not read schema file.")?;
        let schema = from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("Could not deserialize schema file."))?;
        Some(schema)
    } else {
        let res = utils::get_embedded_schema_v0(module);
        if let Err(err) = &res {
            eprintln!("{}", WARNING_STYLE.paint(format!("Could not use embedded schema: {}", err)));
        }
        res.ok()
    };

    let contract_schema_opt = module_schema_opt
        .as_ref()
        .and_then(|module_schema| module_schema.contracts.get(contract_name));
    let contract_schema_state_opt =
        contract_schema_opt.and_then(|contract_schema| contract_schema.state.clone());
    let contract_schema_func_opt = contract_schema_opt.and_then(|contract_schema| {
        if let Some(func) = is_receive {
            contract_schema.receive.get(func)
        } else {
            contract_schema.init.as_ref()
        }
    });

    let print_result = |state: v0::State, logs: v0::Logs| -> anyhow::Result<()> {
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
            _ => eprintln!("The new state is: (No schema found for contract state) {:?}\n", state),
        };

        if let Some(file_path) = &runner.out_bin {
            fs::write(file_path, &state).context("Could not write state to file")?;
        }
        if let Some(file_path) = &runner.out_json {
            contract_schema_opt.context(
                "Schema is required for outputting state in JSON. No schema found for this \
                 contract.",
            )?;
            let schema_state = contract_schema_state_opt.as_ref().context(
                "Schema is required for outputting state in JSON. No schema found the state in \
                 this contract.",
            )?;
            let json_string = schema_state
                .to_json_string_pretty(&state)
                .map_err(|_| anyhow::anyhow!("Could not output contract state in JSON."))?;
            fs::write(file_path, json_string).context("Could not write out the state.")?;
        }
        Ok(())
    };

    let parameter = get_parameter(
        runner.parameter_bin_path.as_deref(),
        runner.parameter_json_path.as_deref(),
        contract_schema_opt.is_some(),
        contract_schema_func_opt,
    )
    .context("Could not get parameter.")?;

    match run_cmd {
        RunCommand::Init {
            ref context,
            ..
        } => {
            let init_ctx: InitContextOpt = match context {
                Some(context_file) => {
                    let ctx_content =
                        fs::read(context_file).context("Could not read init context file.")?;
                    serde_json::from_slice(&ctx_content).context("Could not parse init context.")?
                }
                None => InitContextOpt::default(),
            };
            let name = format!("init_{}", contract_name);
            let res = v0::invoke_init_with_metering_from_source(
                &module,
                runner.amount.micro_ccd,
                init_ctx,
                &name,
                Parameter::from(&parameter[..]),
                runner.energy,
            )
            .context("Invocation failed.")?;
            match res {
                v0::InitResult::Success {
                    logs,
                    state,
                    remaining_energy,
                } => {
                    eprintln!("Init call succeeded. The following logs were produced:");
                    print_result(state, logs)?;
                    eprintln!("Interpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v0::InitResult::Reject {
                    remaining_energy,
                    reason,
                } => {
                    eprintln!("Init call rejected with reason {}.", reason);
                    eprintln!("Interpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v0::InitResult::OutOfEnergy => {
                    eprintln!("Init call terminated with out of energy.")
                }
            }
        }
        RunCommand::Receive {
            ref func,
            ref state_bin_path,
            ref state_json_path,
            balance,
            ref context,
            ..
        } => {
            let mut receive_ctx: ReceiveContextOpt = match context {
                Some(context_file) => {
                    let ctx_content =
                        fs::read(context_file).context("Could not read receive context file.")?;
                    serde_json::from_slice(&ctx_content)
                        .context("Could not parse receive context.")?
                }
                None => ReceiveContextOpt::default(),
            };
            if let Some(balance) = balance {
                receive_ctx.self_balance =
                    Some(concordium_contracts_common::Amount::from_micro_ccd(balance));
            }

            // initial state of the smart contract, read from either a binary or json file.
            let init_state = match (state_bin_path, state_json_path) {
                (None, None) => bail!(
                    "The current state is required for simulating an update to a contract \
                     instance. Use either --state-bin or --state-json."
                ),
                (Some(_), Some(_)) => {
                    bail!("Only one state is allowed, choose either --state-bin or --state-json.")
                }
                (Some(file_path), None) => {
                    let mut file = File::open(&file_path).context("Could not read state file.")?;
                    let metadata = file.metadata().context("Could not read file metadata.")?;
                    let mut init_state = Vec::with_capacity(metadata.len() as usize);
                    file.read_to_end(&mut init_state).context("Reading the state file failed.")?;
                    init_state
                }
                (None, Some(file_path)) => {
                    let schema_state = contract_schema_state_opt
                        .as_ref()
                        .context("A schema for the state must be present to use JSON.")?;
                    let file = fs::read(&file_path).context("Could not read state file.")?;
                    let state_json: serde_json::Value =
                        serde_json::from_slice(&file).context("Could not parse state JSON.")?;
                    let mut state_bytes = Vec::new();
                    write_bytes_from_json_schema_type(&schema_state, &state_json, &mut state_bytes)
                        .context("Could not generate state bytes using schema and JSON.")?;
                    state_bytes
                }
            };

            let name = format!("{}.{}", contract_name, func);
            let res = v0::invoke_receive_with_metering_from_source(
                &module,
                runner.amount.micro_ccd,
                receive_ctx,
                &init_state,
                &name,
                Parameter::from(&parameter[..]),
                runner.energy,
            )
            .context("Calling receive failed.")?;
            match res {
                v0::ReceiveResult::Success {
                    logs,
                    state,
                    actions,
                    remaining_energy,
                } => {
                    eprintln!("Receive method succeeded. The following logs were produced.");
                    print_result(state, logs)?;
                    eprintln!("The following actions were produced.");
                    for (i, action) in actions.iter().enumerate() {
                        match action {
                            v0::Action::Send {
                                data,
                            } => {
                                let name_str = std::str::from_utf8(&data.name)
                                    .context("Target name is not a valid UTF8 sequence.")?;
                                eprintln!(
                                    "{}: send a message to contract at ({}, {}), calling method \
                                     {} with amount {} and parameter {:?}",
                                    i,
                                    data.to_addr.index,
                                    data.to_addr.subindex,
                                    name_str,
                                    data.amount,
                                    parameter
                                )
                            }
                            v0::Action::SimpleTransfer {
                                data,
                            } => {
                                eprintln!(
                                    "{}: simple transfer to account {} of amount {}",
                                    i,
                                    serde_json::to_string(&data.to_addr)
                                        .context("Address not valid JSON, should not happen.")?,
                                    data.amount
                                );
                            }
                            v0::Action::And {
                                l,
                                r,
                            } => eprintln!("{}: AND composition of {} and {}", i, l, r),
                            v0::Action::Or {
                                l,
                                r,
                            } => eprintln!("{}: OR composition of {} and {}", i, l, r),
                            v0::Action::Accept => eprintln!("{}: ACCEPT", i),
                        }
                    }

                    eprintln!("Interpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v0::ReceiveResult::Reject {
                    remaining_energy,
                    reason,
                } => {
                    eprintln!("Receive call rejected with reason {}", reason);
                    eprintln!("Interpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v0::ReceiveResult::OutOfEnergy => {
                    eprintln!("Receive call terminated with: out of energy.")
                }
            }
        }
    }
    Ok(())
}

fn handle_run_v1(run_cmd: RunCommand, module: &[u8]) -> anyhow::Result<()> {
    let (contract_name, runner, is_receive) = match run_cmd {
        RunCommand::Init {
            ref runner,
            ref contract_name,
            ..
        } => (contract_name, runner, None),
        RunCommand::Receive {
            ref runner,
            ref contract_name,
            ref func,
            ..
        } => (contract_name, runner, Some(func)),
    };

    // get the module schema if available.
    let module_schema_opt = if let Some(schema_path) = &runner.schema_path {
        let bytes = fs::read(schema_path).context("Could not read schema file.")?;
        let schema = from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("Could not deserialize schema file."))?;
        Some(schema)
    } else {
        let res = utils::get_embedded_schema_v1(module);
        if let Err(err) = &res {
            eprintln!("{}", WARNING_STYLE.paint(format!("Could not use embedded schema: {}", err)));
        }
        res.ok()
    };

    let contract_schema_opt = module_schema_opt
        .as_ref()
        .and_then(|module_schema| module_schema.contracts.get(contract_name));
    let contract_schema_func_opt = contract_schema_opt.and_then(|contract_schema| {
        if let Some(func) = is_receive {
            contract_schema.receive.get(func)
        } else {
            contract_schema.init.as_ref()
        }
    });

    let print_logs = |logs: v0::Logs| {
        for (i, item) in logs.iterate().enumerate() {
            eprintln!("{}: {:?}", i, item)
        }
    };
    let print_result = |state: v0::State, logs: v0::Logs| -> anyhow::Result<()> {
        print_logs(logs);
        if let Some(file_path) = &runner.out_bin {
            fs::write(file_path, &state.state).context("Could not write state to file")?;
        }
        Ok(())
    };
    let return_value_schema = contract_schema_func_opt.and_then(FunctionSchema::return_value);

    let print_return_value = |rv: ReturnValue| {
        if let Some(schema) = return_value_schema {
            let out = schema
                .to_json_string_pretty(&rv)
                .map_err(|_| anyhow::anyhow!("Could not output return value in JSON"))?;
            eprintln!("Return value: {}", out);
            Ok::<_, anyhow::Error>(())
        } else {
            eprintln!("No schema for the return value. The raw return value is {:?}.", rv);
            Ok(())
        }
    };

    let parameter = get_parameter(
        runner.parameter_bin_path.as_deref(),
        runner.parameter_json_path.as_deref(),
        contract_schema_opt.is_some(),
        contract_schema_func_opt.and_then(FunctionSchema::parameter),
    )
    .context("Could not get parameter.")?;

    match run_cmd {
        RunCommand::Init {
            ref context,
            ..
        } => {
            let init_ctx: InitContextOpt = match context {
                Some(context_file) => {
                    let ctx_content =
                        fs::read(context_file).context("Could not read init context file.")?;
                    serde_json::from_slice(&ctx_content).context("Could not parse init context.")?
                }
                None => InitContextOpt::default(),
            };
            let name = format!("init_{}", contract_name);
            let res = v1::invoke_init_with_metering_from_source(
                &module,
                runner.amount.micro_ccd,
                init_ctx,
                &name,
                &parameter,
                runner.energy,
            )
            .context("Invocation failed.")?;
            match res {
                v1::InitResult::Success {
                    logs,
                    state,
                    remaining_energy,
                    return_value,
                } => {
                    eprintln!("Init call succeeded. The following logs were produced:");
                    print_result(state, logs)?;
                    eprintln!("\nThe following return value was returned.");
                    print_return_value(return_value)?;
                    eprintln!("\nInterpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v1::InitResult::Reject {
                    remaining_energy,
                    reason,
                    return_value,
                } => {
                    eprintln!("Init call rejected with reason {}.", reason);
                    eprintln!("\nThe following return value was returned.");
                    print_return_value(return_value)?;
                    eprintln!("\nInterpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v1::InitResult::OutOfEnergy => {
                    eprintln!("Init call terminated with out of energy.")
                }
            }
        }
        RunCommand::Receive {
            ref func,
            ref state_bin_path,
            balance,
            ref context,
            ..
        } => {
            let mut receive_ctx: ReceiveContextOpt = match context {
                Some(context_file) => {
                    let ctx_content =
                        fs::read(context_file).context("Could not read receive context file.")?;
                    serde_json::from_slice(&ctx_content)
                        .context("Could not parse receive context.")?
                }
                None => ReceiveContextOpt::default(),
            };
            if let Some(balance) = balance {
                receive_ctx.self_balance =
                    Some(concordium_contracts_common::Amount::from_micro_ccd(balance));
            }

            // initial state of the smart contract, read from either a binary or json file.
            let init_state = match state_bin_path {
                None => bail!(
                    "The current state is required for simulating an update to a contract \
                     instance. Use --state-bin."
                ),
                Some(file_path) => {
                    let mut file = File::open(&file_path).context("Could not read state file.")?;
                    let metadata = file.metadata().context("Could not read file metadata.")?;
                    let mut init_state = Vec::with_capacity(metadata.len() as usize);
                    file.read_to_end(&mut init_state).context("Reading the state file failed.")?;
                    init_state
                }
            };

            let name = format!("{}.{}", contract_name, func);
            let res = v1::invoke_receive_with_metering_from_source::<
                ReceiveContextOpt,
                ReceiveContextOpt,
            >(
                &module,
                runner.amount.micro_ccd,
                receive_ctx,
                &init_state,
                &name,
                &parameter,
                runner.energy,
            )
            .context("Calling receive failed.")?;
            match res {
                v1::ReceiveResult::Success {
                    logs,
                    state,
                    remaining_energy,
                    return_value,
                } => {
                    eprintln!("Receive method succeeded. The following logs were produced.");
                    print_result(state, logs)?;
                    eprintln!("\nThe following return value was returned.");
                    print_return_value(return_value)?;
                    eprintln!("\nInterpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v1::ReceiveResult::Reject {
                    remaining_energy,
                    reason,
                    return_value,
                } => {
                    eprintln!("Receive call rejected with reason {}", reason);
                    eprintln!("\nThe following return value was returned.");
                    print_return_value(return_value)?;
                    eprintln!("\nInterpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v1::ReceiveResult::OutOfEnergy => {
                    eprintln!("Receive call terminated with: out of energy.")
                }
                v1::ReceiveResult::Interrupt {
                    remaining_energy,
                    logs,
                    config: _,
                    interrupt,
                } => {
                    eprintln!(
                        "Receive method was interrupted. The following logs were produced by the \
                         time of the interrupt."
                    );
                    print_logs(logs);
                    match interrupt {
                        v1::Interrupt::Transfer {
                            to,
                            amount,
                        } => eprintln!(
                            "Receive call invoked a transfer of {} CCD to {}.",
                            amount, to
                        ),
                        v1::Interrupt::Call {
                            address,
                            parameter,
                            name,
                            amount,
                        } => eprintln!(
                            "Receive call invoked contract at ({}, {}), calling method {} with \
                             amount {} and parameter {:?}.",
                            address.index, address.subindex, name, amount, parameter
                        ),
                    }
                    eprintln!("Interpreter energy spent is {}", runner.energy - remaining_energy)
                }
                v1::ReceiveResult::Trap {
                    remaining_energy,
                    error,
                } => {
                    return Err(error.context(format!(
                        "Execution triggered a runtime error after spending {} interpreter energy.",
                        runner.energy - remaining_energy
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Attempt to get a parameter (for either init or receive function) from the
/// supplied paths, signalling failure if this is not possible.
fn get_parameter(
    bin_path: Option<&Path>,
    json_path: Option<&Path>,
    has_contract_schema: bool,
    parameter_schema: Option<&Type>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(param_file) = bin_path {
        fs::read(&param_file).context("Could not read parameter-bin file.")
    } else if let Some(param_file) = json_path {
        if !has_contract_schema {
            Err(anyhow::anyhow!(
                "No schema found for contract, a schema is required for using --parameter-json."
            ))
        } else {
            let parameter_schema = parameter_schema
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
}
