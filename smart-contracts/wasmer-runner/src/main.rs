use clap::AppSettings;
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};
use structopt::StructOpt;
use wasmer_interp::*;

#[derive(StructOpt)]
#[structopt(about = "Simple smart contract runner.", author = "Concordium", version = "0.12345")]
struct WasmerRunner {
    #[structopt(
        name = "source",
        long = "source",
        global = true,
        default_value = "contract.wasm",
        help = "Binary module source."
    )]
    source: PathBuf,
    #[structopt(
        name = "out",
        long = "out",
        global = true,
        help = "Where to write the new contract state to. Defaults to stdout if not given."
    )]
    out: Option<PathBuf>,
    #[structopt(
        name = "hex",
        long = "hex",
        global = true,
        help = "Whether to write the state as a hex string or not. Defaults to binary."
    )]
    hex_state: bool,
    #[structopt(
        name = "amount",
        long = "amount",
        global = true,
        help = "The amount to invoke the method with.",
        default_value = "0"
    )]
    amount: u64,
    #[structopt(
        name = "parameter",
        long = "parameter",
        global = true,
        help = "Path to a file with a parameter to invoke the method with. Parameter defaults to \
                an empty array if this is not given."
    )]
    parameter: Option<PathBuf>,
    #[structopt(flatten)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
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
    },
    #[structopt(name = "update", about = "Invoke a receive method of a module.")]
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
    },
}

pub fn main() {
    let runner = {
        let app = WasmerRunner::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        WasmerRunner::from_clap(&matches)
    };

    let source = {
        let mut source = Vec::new();
        let mut file = File::open(&runner.source).expect("Could not read file.");
        file.read_to_end(&mut source).expect("Reading the source file failed.");
        source
    };

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
                    let mut out_file = File::create(fp).expect("Could not create output file.");
                    out_file.write_all(output.as_bytes()).expect("Could not write out the state.");
                }
            }
        } else {
            match &runner.out {
                None => println!("The new state is: {:?}", state),
                Some(fp) => {
                    let mut out_file = File::create(fp).expect("Could not create output file.");
                    out_file.write_all(&state).expect("Could not write out the state.")
                }
            }
        }
    };

    let parameter = {
        match &runner.parameter {
            None => Vec::new(),
            Some(param_file) => {
                let mut param_file =
                    File::open(&param_file).expect("Could not open parameter file.");
                let mut input = Vec::new();
                param_file.read_to_end(&mut input).expect("Could not read from parameter file.");
                input
            }
        }
    };

    match runner.command {
        Command::Init {
            ref name,
            ref context,
        } => {
            let init_ctx = {
                let ctx_file = File::open(context).expect("Could not open context file.");
                serde_json::from_reader(std::io::BufReader::new(ctx_file))
                    .expect("Could not parse init context")
            };
            if let InitResult::Success {
                logs,
                state,
            } = invoke_init(&source, runner.amount, init_ctx, &name, parameter)
                .expect("Invocation failed.")
            {
                println!("Init call succeeded. The following logs were produced.");
                print_result(state, logs)
            } else {
                println!("Init call rejected.")
            }
        }
        Command::Receive {
            ref name,
            ref state,
            balance,
            ref context,
        } => {
            let mut receive_ctx: contracts_common::ReceiveContext = {
                let ctx_file = File::open(context).expect("Could not open context file.");
                serde_json::from_reader(std::io::BufReader::new(ctx_file))
                    .expect("Could not parse init context")
            };
            if let Some(balance) = balance {
                receive_ctx.self_balance = balance;
            }

            // initial state of the smart contract, read from a file.
            let init_state = {
                let mut file = File::open(&state).expect("Could not read state file.");
                let metadata = file.metadata().expect("Could not read file metadata.");
                let mut init_state = Vec::with_capacity(metadata.len() as usize);
                file.read_to_end(&mut init_state).expect("Reading the state file failed.");
                init_state
            };
            let res =
                invoke_receive(&source, runner.amount, receive_ctx, &init_state, &name, parameter)
                    .expect("Calling receive failed.");
            match res {
                ReceiveResult::Success {
                    logs,
                    state,
                    actions,
                    ..
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
                                "{}: send a message to contract at ({}, {}), calling method {:?} \
                                 with amount {} and parameter {:?}",
                                i, to_addr.index, to_addr.subindex, name, amount, parameter
                            ),
                            Action::SimpleTransfer {
                                to_addr,
                                amount,
                            } => {
                                println!(
                                    "{}: simple transfer to account {} of amount {}",
                                    i,
                                    serde_json::to_string(to_addr)
                                        .expect("Address not valid JSON, should not happen."),
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
                }
                ReceiveResult::Reject {
                    logs,
                } => {
                    for (i, item) in logs.iterate().iter().enumerate() {
                        if let Ok(s) = std::str::from_utf8(item) {
                            println!("{}: {}", i, s)
                        } else {
                            println!("{}: {:?}", i, item)
                        }
                    }
                    println!("Receive call rejected.")
                }
            }
        }
    }
}
