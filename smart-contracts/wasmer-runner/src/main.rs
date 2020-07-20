use clap::AppSettings;
use std::{
    convert::TryInto,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};
use structopt::StructOpt;
use wasmer_interp::*;

#[derive(StructOpt)]
struct CommonOptions {
    #[structopt(name = "source", long = "source", about = "Binary module source.")]
    source: PathBuf,
    #[structopt(
        name = "out",
        long = "out",
        about = "Where to write the new contract state to. Defaults to stdout if not given."
    )]
    out: Option<PathBuf>,
    #[structopt(
        name = "hex",
        long = "hex",
        about = "Whether to write the state as a hex string or not. Defaults to binary."
    )]
    hex_state: bool,
    #[structopt(
        name = "amount",
        long = "amount",
        about = "The amount to invoke the method with.",
        default_value = "0"
    )]
    amount: u64,
    #[structopt(
        name = "sender",
        long = "sender",
        about = "Who is sending this transaction, an account address."
    )]
    // FIXME: We use base16 encoding for testing for now.
    sender: String,
    // TODO: Parameter
}

#[derive(StructOpt)]
#[structopt(about = "Simple smart contract runner.", author = "Concordium", version = "0.12345")]
enum WasmerRunner {
    #[structopt(name = "init", about = "Initialize a module.")]
    Init {
        #[structopt(flatten)]
        common: CommonOptions,
        #[structopt(
            name = "name",
            long = "name",
            about = "Name of the method to invoke.",
            default_value = "init"
        )]
        name: String,
    },
    #[structopt(name = "update", about = "Invoke a receive method of a module.")]
    Receive {
        #[structopt(flatten)]
        common: CommonOptions,
        #[structopt(
            name = "name",
            long = "name",
            about = "Name of the method to invoke.",
            default_value = "receive"
        )]
        name: String,
        #[structopt(
            name = "state",
            long = "state",
            about = "File with existing state of the contract."
        )]
        state: PathBuf,
        #[structopt(
            name = "contract-address",
            long = "contract-address",
            about = "Index of the contract address.",
            default_value = "0"
        )]
        index: u64,
        #[structopt(
            name = "contract-subindex",
            long = "contract-subindex",
            about = "Subindex of the contract address.",
            default_value = "0"
        )]
        subindex: u64,
        #[structopt(
            name = "balance",
            long = "balance",
            about = "Balance on the contract at the time it is invoked.",
            default_value = "0"
        )]
        balance: u64,
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

    let common = match runner {
        WasmerRunner::Init {
            ref common,
            ..
        } => common,
        WasmerRunner::Receive {
            ref common,
            ..
        } => common,
    };
    let addr = match hex::decode(&common.sender) {
        Ok(addr) if addr.len() == 32 => addr,
        _ => {
            eprintln!("Address decoding failed.");
            return;
        }
    };
    let source = {
        let mut source = Vec::new();
        let mut file = File::open(&common.source).expect("Could not read file.");
        file.read_to_end(&mut source).expect("Reading the source file failed.");
        source
    };

    let print_result = |state: State, logs: Logs| {
        for (i, item) in logs.iterate().iter().enumerate() {
            println!("{}: {:?}", i, item)
        }
        let state = state.get();
        if common.hex_state {
            let output = hex::encode(&state);
            match &common.out {
                None => println!("The new state is: {}", output),
                Some(fp) => {
                    let mut out_file = File::create(fp).expect("Could not create output file.");
                    out_file.write_all(output.as_bytes()).expect("Could not write out the state.");
                }
            }
        } else {
            match &common.out {
                None => println!("The new state is: {:?}", state),
                Some(fp) => {
                    let mut out_file = File::create(fp).expect("Could not create output file.");
                    out_file.write_all(&state).expect("Could not write out the state.")
                }
            }
        }
    };

    match runner {
        WasmerRunner::Init {
            name,
            ..
        } => {
            let init_ctx = InitContext {
                init_origin: addr[..].try_into().unwrap(),
            };
            if let InitResult::Success {
                logs,
                state,
            } = invoke_init(&source, common.amount, init_ctx, &name).expect("Invocation failed.")
            {
                println!("Init method run. The following logs were produced.");
                print_result(state, logs)
            } else {
                println!("Init call rejected.")
            }
        }
        WasmerRunner::Receive {
            name,
            state,
            index,
            subindex,
            balance,
            ..
        } => {
            let receive_ctx = ReceiveContext {
                invoker:      addr[..].try_into().unwrap(),
                self_address: ContractAddress {
                    index,
                    subindex,
                },
                self_balance: balance,
            };
            // initial state of the smart contract, read from a file.
            let init_state = {
                let mut file = File::open(&state).expect("Could not read state file.");
                let metadata = file.metadata().expect("Could not read file metadata.");
                let mut init_state = Vec::with_capacity(metadata.len() as usize);
                file.read_to_end(&mut init_state).expect("Reading the state file failed.");
                init_state
            };
            if let ReceiveResult::Success {
                logs,
                state,
                ..
            } = invoke_receive(&source, common.amount, receive_ctx, &init_state, &name)
                .expect("Calling receive failed.")
            {
                println!("Receive method run. The following logs were produced.");
                print_result(state, logs)
            } else {
                println!("Receive call rejected.")
            }
        }
    }
}
